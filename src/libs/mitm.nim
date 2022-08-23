import std/[asyncnet, asyncdispatch, nativesockets,
            strutils, strformat,streams, logging,
            net, tables, oids]
import parser, reader, certman, utils

let BAD_REQUEST = "HTTP/1.1 400 BAD REQUEST\r\nConnection: close\r\n\r\n"
let OK = "HTTP/1.1 200 OK\r\n\r\n"
let NOT_IMPLEMENTED = "HTTP/1.1 501 NOT IMPLEMENTED\r\nConnection: close\r\n\r\n"
let NOT_FOUND = "HTTP/1.1 404 NOT FOUND\r\nConnection: close\r\n\r\n"


proc sendRawRequest(target: AsyncSocket, 
                    req: string): Future[tuple[headers: string, 
                                               body: string]] {.async.} =
    ## This proc sends the given raw HTML request (req) through the given socket (target).
    ## Returns a future tuple containing the headers an body of the response.
    await target.send(req)
    if req.startsWith("HEAD") or req.startsWith("TRACE"):
        result = await target.readHTTPRequest(body=false)
    else:
        result = await target.readHTTPRequest()


proc tunnel(src: AsyncSocket, 
            dst: AsyncSocket, cid: string): Future[string] {.async.} =
    ## Tunnels two given socket who are actively connected to a destination.
    ## The tunnel will continue as long as data comes through, 
    ## until a predetermined timeout, then it closes each sockets.
    ## The timeout is 1 second for now. (this should be configurable)
    ## Does not handle connection of the sockets, only the closure.
    let src_addr = src.getPeerAddr()
    let dst_addr = dst.getPeerAddr()
    var excluded: bool
    let stream = newStringStream()
    defer: stream.close()
    proc srcHasData() {.async.} =
        try:
            while not src.isClosed and not dst.isClosed:
                log(lvlDebug, fmt"[{cid}][tunnel][{src_addr} -->> {dst_addr}[SRC] recv.")
                let data = src.recv(4096)
                let future = await withTimeout(data, 2000)
                if future and data.read.len() != 0 and not dst.isClosed:
                    log(lvlDebug, fmt"[{cid}][tunnel][{src_addr} -->> {dst_addr}][SRC] sending to DST.")
                    await dst.send(removeEncoding(data.read))
                    log(lvlDebug, fmt"[{cid}][tunnel][{src_addr} -->> {dst_addr}][SRC] sent.")
                    if not excluded:
                        stream.write(data.read)
                        excluded = excludeData(data.read)
                else:
                    break
        except:
            log(lvlError, fmt"[{cid}][tunnel][{src_addr}] " & getCurrentExceptionMsg())

    proc dstHasData() {.async.} =
        try:
            while not dst.isClosed and not src.isClosed:
                log(lvlDebug, fmt"[{cid}][tunnel][{src_addr} <<-- {dst_addr}][DST] recv.")
                let data = dst.recv(4096)
                let future = await withTimeout(data, 1500)
                if future and data.read.len() != 0 and not src.isClosed:
                    log(lvlDebug, fmt"[{cid}][tunnel][{src_addr} <<-- {dst_addr}][DST] sending to SRC.")
                    await src.send(data.read)
                    log(lvlDebug, fmt"[{cid}][tunnel][{src_addr} <<-- {dst_addr}][DST] sent.")
                    if not excluded:
                        stream.write(data.read)
                        excluded = excludeData(data.read)
                else:
                    break
        except:
            log(lvlError, fmt"[{cid}][tunnel][{src_addr} -->> {dst_addr}] " & getCurrentExceptionMsg())

    await srcHasData() and dstHasData() 
    log(lvlDebug, fmt"[{cid}][tunnel][{src_addr} -->> {dst_addr}] excluded: " & $excluded)
    if not excluded:
        stream.setPosition(0)
        result = stream.readAll()


proc mitmHttp(client: AsyncSocket, 
              host: string, port: int, 
              req: string, cid: string): Future[string] {.async.} = 
        ## Man in the Middle a given connection to its desired destination.
        ## For HTTP, we simply forward the request and save the response.
        ## Returns the interaction, containing the request and response in full.
        let remote = newAsyncSocket(buffered=false)
        try:
            await remote.connect(host, Port(port))
            var res_info = await remote.sendRawRequest(req)
            await client.send(res_info.headers & res_info.body)
            return req & "\r\n" & res_info.headers & res_info.body
        except:
            log(lvlError, fmt"[{cid}][mitmHTTP] Could not resolve remote, terminating connection.")
            await client.send(NOT_FOUND)
        finally:
            log(lvlDebug, fmt"[{cid}][mitmHTTP] Done, closing.")
            remote.close()
            client.close()


proc mitmHttps(client: AsyncSocket, 
               host: string, 
               port: int, cid: string): Future[string] {.async.} =
    ## Man in the Middle a given connection to its desired destination.
    ## For HTTPS, we negotiate ssl on the given client socket.
    ## Then we connect to the desired destination with the right ssl context.
    ## Finally, we tunnel these two sockets together while saving the data in between.
    ## Returns the interaction, containing the request and response in full.
    if not handleHostCertificate(host):
        log(lvlError,
            fmt"[{cid}][mitmHTTPS] Error occured while generating certificate for {host}.")
        await client.send(BAD_REQUEST)

    let remote = newAsyncSocket(buffered=false)
    let remote_ctx = newContext(verifyMode = CVerifyNone)
    wrapSocket(remote_ctx, remote)
    try:
        await remote.connect(host, Port(port))
    except:
        log(lvlError, fmt"[{cid}][mitmHTTPS] Could not resolve remote, terminating connection.")
        await client.send(NOT_FOUND)
    await client.send(OK)

    let ctx = getMITMContext(host)
    wrapConnectedSocket(ctx, client, handshakeAsServer, hostname = host)
    try:
        result = await tunnel(client, remote, cid)
    except:
        log(lvlError, "")
    client.close()
    remote.close()
    log(lvlInfo, fmt"[{cid}][mitmHTTPS] Connection done.")


proc processClient(client: AsyncSocket, cid: string) {.async.} =
    ## Processes and incoming request by parsing it.
    ## Forward the client to the right MITM handler, then persists the interaction.
    ## If requestline is CONNECT, treat as https, else http.
    let req = await readHTTPRequest(client)
    var headers = parseHeaders(req.headers)
    var requestline = 
        if headers.hasKey("requestline"): 
            headers["requestline"].split(" ") 
        else: 
            @[""]

    if requestline == @[""]:
        log(lvlError, fmt"[{cid}][processClient] Invalid requestline, terminating connection.")
        log(lvlDebug, fmt"[{cid}][processClient] {headers}")
        await client.send(BAD_REQUEST)
        client.close()
        return

    var (proto, host, port, route) = parseProxyHost(requestline[1])
    if host == "":
        log(lvlError, fmt"[{cid}][processClient] Invalid host, terminating connection.")
        await client.send(BAD_REQUEST)
        client.close()
        return

    var interaction: string
    if requestline[0] != "CONNECT" and proto == "http":
        log(lvlInfo,
            fmt"[{cid}][processClient][HTTP] MITM Tunneling | {client.getPeerAddr()[0]} ->> {host}:{port}.")
        requestline[1] = route
        headers["requestline"] = join(requestline, " ") 
        var req = proxyHeaders(headers) & req.body
        interaction = await mitmHttp(client, host, port, req, cid)
    else:
        log(lvlInfo, 
            fmt"[{cid}][processClient][HTTPS] MITM Tunneling | {client.getPeerAddr()[0]} ->> {host}:{port}.")
        interaction = await mitmHttps(client, host, port, cid)

    if interaction != "":
       # DEVNOTE: to debug -- write raw streams
       # let f = open(fmt"interactions/streams/{cid}", fmWrite)
       # f.write(interaction)
       # f.close()
       if not saveInteraction(host, port, cid, parseRequest(interaction, cid)):
           log(lvlError, fmt"[{cid}] Error while writing interaction to filesystem.")


proc startMITMProxy*(address: string, port: int) {.async.} = 
    ## Wrapper proc to start the MITMProxy.
    ## Will listen and process clients until stopped on the provided address:port.
    let server = newAsyncSocket(buffered=false)
    server.setSockOpt(OptReuseAddr, true) 
    server.bindAddr(Port(port), address)
    try:
        server.listen()
        log(lvlInfo, "STARTED")
        var client = newAsyncSocket(buffered=false)
        while true:
           client = await server.accept()
           asyncCheck processClient(client, $genOid()) 
    except:
       log(lvlError, "[start] " & getCurrentExceptionMsg())
    finally:
        server.close()
