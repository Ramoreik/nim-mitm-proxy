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
    let baseLog = fmt"[{cid}][tunnel][{src_addr[0]}:{src_addr[1]} $1 {dst_addr[0]}:{dst_addr[1]}][$2] "
    var excluded: bool
    let stream = newStringStream()
    defer: stream.close()
    proc srcHasData() {.async.} =
        try:
            while not src.isClosed and not dst.isClosed:
                log(lvlDebug, baseLog % ["-->>", "SRC"] & "recv.")
                let data = src.recv(4096)
                let future = await withTimeout(data, 2000)
                if future and data.read.len() != 0 and not dst.isClosed:
                    await dst.send(removeEncoding(data.read))
                    log(lvlDebug, baseLog % ["-->>", "SRC"] & "sent.")
                    if not excluded:
                        stream.write(data.read)
                        excluded = excludeData(data.read)
                else:
                    break
        except:
            log(lvlError, baseLog % ["--/--", "SRC"] & getCurrentExceptionMsg())

    proc dstHasData() {.async.} =
        try:
            while not dst.isClosed and not src.isClosed:
                log(lvlDebug, baseLog % ["<<--", "DST"] & "recv.")
                let data = dst.recv(4096)
                let future = await withTimeout(data, 1500)
                if future and data.read.len() != 0 and not src.isClosed:
                    await src.send(data.read)
                    log(lvlDebug, baseLog % ["<<--", "DST"] & "sent.")
                    if not excluded:
                        stream.write(data.read)
                        excluded = excludeData(data.read)
                else:
                    break
        except:
            log(lvlError, baseLog % ["--\\--", "DST"] & getCurrentExceptionMsg())

    await srcHasData() and dstHasData() 

    let indicator = if excluded: "--X--" else: "-----"
    log(lvlDebug, 
        baseLog % [indicator, "DONE"] & fmt"[excluded: {$excluded}]")
    if not excluded:
        stream.setPosition(0)
        result = stream.readAll()


proc mitmHttp(client: AsyncSocket, 
              host: string, port: int, 
              req: string, cid: string): Future[string] {.async.} = 
    ## Man in the Middle a given connection to its desired destination.
    ## For HTTP, we simply forward the request and save the response.
    ## Returns the interaction, containing the request and response in full.
    let baseLog = fmt"[{cid}][mitmHTTP] "
    let remote = newAsyncSocket(buffered=false)
    try:
        await remote.connect(host, Port(port))
        var res_info = await remote.sendRawRequest(req)
        await client.send(res_info.headers & res_info.body)
        return req & "\r\n" & res_info.headers & res_info.body
    except:
        log(lvlError, baseLog & "Could not resolve remote, terminating connection.")
        await client.send(NOT_FOUND)
    finally:
        log(lvlDebug, baseLog & "Done, closing.")
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
    let baseLog = fmt"[{cid}][mitmHTTP] "
    if not handleHostCertificate(host):
        log(lvlError,
            baseLog & fmt"Error occured while generating certificate for {host}.")
        await client.send(BAD_REQUEST)

    let remote = newAsyncSocket(buffered=false)
    let remote_ctx = newContext(verifyMode = CVerifyNone)
    wrapSocket(remote_ctx, remote)
    try:
        await remote.connect(host, Port(port))
    except:
        log(lvlError, baseLog & "Could not resolve remote, terminating connection.")
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
    log(lvlInfo, baseLog & "Connection done.")


proc processClient(client: AsyncSocket, cid: string) {.async.} =
    ## Processes and incoming request by parsing it.
    ## Forward the client to the right MITM handler, then persists the interaction.
    ## If requestline is CONNECT, treat as https, else http.
    let baseLog = fmt"[{cid}][processClient]"
    let tunnelingLog = 
        baseLog & fmt"[$1] MITM Tunneling | {client.getPeerAddr()[0]} ->> {$2}:{$3}."
    let req = await readHTTPRequest(client)
    var headers = parseHeaders(req.headers)
    var requestline = 
        if headers.hasKey("requestline"): 
            headers["requestline"].split(" ") 
        else: 
            @[""]

    if requestline == @[""]:
        log(lvlError, baseLog & "Invalid requestline, terminating connection.")
        log(lvlDebug, baseLog & "{headers}")
        await client.send(BAD_REQUEST)
        client.close()
        return

    var (proto, host, port, route) = parseProxyHost(requestline[1])
    if host == "":
        log(lvlError, baseLog & "Invalid host, terminating connection.")
        await client.send(BAD_REQUEST)
        client.close()
        return

    var interaction: string
    if requestline[0] != "CONNECT" and proto == "http":
        log(lvlInfo, tunnelingLog % ["HTTP", host, $port])
        requestline[1] = route
        headers["requestline"] = join(requestline, " ") 
        var req = proxyHeaders(headers) & req.body
        interaction = await mitmHttp(client, host, port, req, cid)
    else:
        log(lvlInfo, tunnelingLog % ["HTTPS", host, $port])
        interaction = await mitmHttps(client, host, port, cid)

    if interaction != "":
       if not saveInteraction(host, port, cid, parseRequest(interaction, cid)):
           log(lvlError, 
               baseLog & "Error while writing interaction to filesystem.")


proc startMITMProxy*(address: string, port: int) {.async.} = 
    ## Wrapper proc to start the MITMProxy.
    ## Will listen and process clients until stopped on the provided address:port.
    let server = newAsyncSocket(buffered=false)
    server.setSockOpt(OptReuseAddr, true) 
    server.bindAddr(Port(port), address)
    try:
        server.listen()
        log(lvlInfo, "[STARTED OK]")
        var client = newAsyncSocket(buffered=false)
        while true:
           client = await server.accept()
           asyncCheck processClient(client, $genOid()) 
    except:
       log(lvlError, "[start] " & getCurrentExceptionMsg())
    finally:
        server.close()
