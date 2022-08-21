import std/[asyncnet, asyncdispatch, 
            strutils ,streams, logging,
            strformat, net, tables, os]
import parser, reader, certman, utils

let BAD_REQUEST = "HTTP/1.1 400 BAD REQUEST\r\nConnection: close\r\n\r\n"
let OK = "HTTP/1.1 200 OK\r\n\r\n"
let NOT_IMPLEMENTED = "HTTP/1.1 501 NOT IMPLEMENTED\r\nConnection: close\r\n\r\n"
let NOT_FOUND = "HTTP/1.1 404 NOT FOUND\r\nConnection: close\r\n\r\n"

proc sendRawRequest(target: AsyncSocket, req: string): 
        Future[tuple[headers: string, body: string]] {.async.} =
    await target.send(req)
    if req.startsWith("HEAD") or req.startsWith("TRACE"):
        result = await target.readHTTPRequest(body=false)
    else:
        result = await target.readHTTPRequest()


proc tunnel(src: AsyncSocket, 
            dst: AsyncSocket): Future[tuple[src_data: string, dst_data: string]] {.async.} =
    var src_data = newStringStream()
    var dst_data = newStringStream()
    var excluded: bool
    proc srcHasData() {.async.} =
        try:
            while not src.isClosed and not dst.isClosed:
                log(lvlDebug, "[tunnel][SRC] recv.")
                let data = src.recv(4096)
                let fut_data = await withTimeout(data, 2000)
                if fut_data and data.read.len() != 0 and not dst.isClosed:
                    log(lvlDebug, "[tunnel][SRC] sending to DST.")
                    if not excluded:
                        let pos = src_data.getPosition()
                        src_data.write(data.read)
                        excluded = excludeData(src_data.readAll())
                        src_data.setPosition(pos)
                    else:
                        src_data.close()
                    await dst.send(data.read)
                    log(lvlDebug, "[tunnel][SRC] sent.")
                else:
                    break
        except:
            log(lvlError, "[tunnel] " & getCurrentExceptionMsg())

    proc dstHasData() {.async.} =
        try:
            while not dst.isClosed and not src.isClosed:
                log(lvlDebug, "[tunnel][DST] recv.")
                let data = dst.recv(4096)
                let fut_data = await withTimeout(data, 1000)
                if fut_data and data.read.len() != 0 and not src.isClosed:
                    log(lvlDebug, "[tunnel][DST] sending to SRC.")
                    if not excluded:
                        let pos = src_data.getPosition()
                        dst_data.write(data.read)
                        excluded = excludeData(dst_data.readAll())
                        dst_data.setPosition(pos)
                    else:
                        dst_data.close()
                    await src.send(data.read)
                    log(lvlDebug, "[tunnel][DST] sent.")
                else:
                    break
        except:
            log(lvlError, "[tunnel] " & getCurrentExceptionMsg())

    await srcHasData() and dstHasData() 
    if not excluded:
        result = (src_data.readAll(), dst_data.readAll())
    else:
        result = ("", "")
    src_data.close()
    dst_data.close()

proc mitmHttp(client: AsyncSocket, host: string, port: int, 
              req: string): Future[string] {.async.} = 
        let remote = newAsyncSocket(buffered=false)
        try:
            # connect to remote
            await remote.connect(host, Port(port))

            # send request to remote
            var res_info = await remote.sendRawRequest(req)

            #send response to client
            await client.send(res_info.headers & res_info.body)
            return res_info.headers & res_info.body
        except:
            log(lvlError, "[processClient] Could not resolve remote, terminating connection.")
            await client.send(NOT_FOUND)
        finally:
            log(lvlDebug, "[processClient][CONNECT] Done, closing.")
            remote.close()
            client.close()

proc mitmHttps(client: AsyncSocket, 
               host: string, 
               port: int): Future[tuple[src_data: string, dst_data: string]] {.async.} =
    # handle certificate
    if not handleHostCertificate(host):
        log(lvlError,
            fmt"[processClient] Error occured while generating certificate for {host}.")
        await client.send(BAD_REQUEST)

    # connect to remote and negotiate SSL
    let remote = newAsyncSocket(buffered=false)
    let remote_ctx = newContext(verifyMode = CVerifyNone)
    wrapSocket(remote_ctx, remote)
    await remote.connect(host, Port(port))

    # confirm tunneling with client
    await client.send(OK)

    # wrap with my own SSL context
    let ctx = getMITMContext(host)
    wrapConnectedSocket(ctx, client, handshakeAsServer, hostname = host)

    # tunnel the two sockets
    result = await tunnel(client, remote)
    client.close()
    remote.close()
    log(lvlInfo, "[start] Connection done.")

proc processClient(client: AsyncSocket) {.async.} =
    let req = await readHTTPRequest(client)
    var headers = parseHeaders(req.headers)
    var requestline = 
        if headers.hasKey("requestline"): 
            headers["requestline"].split(" ") 
        else: 
            @[""]

    if requestline == @[""]:
        log(lvlError, "Invalid requestline, terminating connection.")
        log(lvlDebug, fmt"{headers}")
        await client.send(BAD_REQUEST)
        client.close()
        return

    var (proto, host, port, route) = parseProxyHost(requestline[1])
    if host == "":
        log(lvlError, "Invalid host, terminating connection.")
        await client.send(BAD_REQUEST)
        client.close()
        return

    # if method is not CONNECT, use plain HTTP
    if requestline[0] != "CONNECT":
        if proto == "http":
            log(lvlInfo,
                fmt"[processClient][HTTP] MITM Tunneling | {client.getPeerAddr()[0]} ->> {host}:{port}.")

            # modify host in requestline
            requestline[1] = route
            headers["requestline"] = join(requestline, " ") 

            # construct request for remote
            var req = proxyHeaders(headers) & req.body

            # mitm the connection
            let res = await mitmHttp(client, host, port, req)
            if not saveInteraction(host, port, (req, res)):
                log(lvlError, "Error while writing interaction to filesystem.")
        else:
            log(lvlError, "[processClient] This proxy method is only for HTTP.")
            await client.send(BAD_REQUEST)
            client.close()
    else:
        log(lvlInfo, fmt"[processClient][HTTPS] MITM Tunneling | {client.getPeerAddr()[0]} ->> {host}:{port}.")
        let interaction = await mitmHttps(client, host, port)
        if interaction != ("", ""):
            if not saveInteraction(host, port, interaction):
                log(lvlError, "Error while writing interaction to filesystem.")
proc start*(port: int) = 
    let server = newAsyncSocket(buffered=false)
    server.setSockOpt(OptReuseAddr, true) 
    server.bindAddr(Port(port), "127.0.0.1")
    try:
        server.listen()
        log(lvlInfo, "STARTED")
        var connections = 0
        var client = newAsyncSocket(buffered=false)
        while true:
           client = waitFor server.accept()
           log(lvlDebug, " Connections: " & $connections)
           asyncCheck processClient(client) 
           connections += 1
    except:
       log(lvlError, "[start] " & getCurrentExceptionMsg())
    finally:
        server.close()

