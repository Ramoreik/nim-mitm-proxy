import std/[strutils, strformat, logging,
            asyncnet, os, asyncdispatch, 
            tables, net, osproc]
import libs/[parser, reader, certman]
import cligen

let BAD_REQUEST = "HTTP/1.1 400 BAD REQUEST\r\nConnection: close\r\n\r\n"
let OK = "HTTP/1.1 200 OK\r\n\r\n"
let NOT_IMPLEMENTED = "HTTP/1.1 501 NOT IMPLEMENTED\r\nConnection: close\r\n\r\n"
let NOT_FOUND = "HTTP/1.1 404 NOT FOUND\r\nConnection: close\r\n\r\n"


# inspiration taken from: https://xmonader.github.io/nimdays/day15_tcprouter.html
# by inspiration I mean it saved me hours of trial and error since i'm dumb.

# This project is to learn the concepts involved in HTTP/HTTPS proxying, Websockets proxying and SOCKS. 

# to MITM, i have to place myself as the remote client, when im tunnelling.
# meaning:
# 1 - I wrap the socket intented for the remote server with my ssl context
# 2 - I start another socket and i negotiate ssl to the actual target
# 3 - I tunnel the two and I can read the data in the tunnel.

# For this to work I also have to generate certs on the fly, implemented poorly for now.

# TODO: Add better, granular error handling
# TODO: Fix Edgecases:
    # FIXME: fix edgecase in www.jumpstart.com, site doesn't load for some reason.
    # FIXME: Look into invalid requestlines, happening a lot.
    # FIXME: Investigate weird crash on youtube when browsing videos, only on macos apparently.
    # FIXME: Investigate why ookla speedtest fails, fails everywhere with SIGSVE, no idea why.

# - - - - - - - - - - - - - - - - - -
#  PROXYING
# - - - - - - - - - - - - - - - - - -
proc sendRawRequest(target: AsyncSocket, req: string): 
        Future[tuple[headers: string, body: string]] {.async.} =
    await target.send(req)
    if req.startsWith("HEAD") or req.startsWith("TRACE"):
        result = await target.readHTTPRequest(body=false)
    else:
        result = await target.readHTTPRequest()

proc tunnel(src: AsyncSocket, 
            dst: AsyncSocket): Future[tuple[src_data: string, dst_data: string]] {.async.} =
    proc srcHasData() {.async.} =
        try:
            while not src.isClosed and not dst.isClosed:
                log(lvlDebug, "[tunnel][SRC] recv.")
                let data = src.recv(4096)
                let fut_data = await withTimeout(data, 2000)
                if fut_data and data.read.len() != 0 and not dst.isClosed:
                    log(lvlDebug, "[tunnel][SRC] sending to DST.")
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
                    await src.send(data.read)
                    log(lvlDebug, "[tunnel][DST] sent.")
                else:
                    break
        except:
            log(lvlError, "[tunnel] " & getCurrentExceptionMsg())
    await srcHasData() and dstHasData() 

# - - - - - - - - - - - - - - - - - -
#  Server + client handling
# - - - - - - - - - - - - - - - - - -

proc mitmHttp(client: AsyncSocket, host: string, port: int, 
              req: string) {.async.} = 
        let remote = newAsyncSocket(buffered=false)
        try:
            # connect to remote
            await remote.connect(host, Port(port))

            # send request to remote
            var res_info = await remote.sendRawRequest(req)

            #send response to client
            await client.send(res_info.headers & res_info.body)
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
    log(lvlDebug, "[start] Connection done.")

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
            await mitmHttp(client, host, port, req)
        else:
            log(lvlError, "[processClient] This proxy method is only for HTTP.")
            await client.send(BAD_REQUEST)
            client.close()
    else:
        log(lvlInfo, fmt"[processClient][HTTPS] MITM Tunneling | {client.getPeerAddr()[0]} ->> {host}:{port}.")
        let (src_data, dst_data) = await mitmHttps(client, host, port)

proc setupLogging() = 
    var stdout = newConsoleLogger(
        fmtStr = "[$time][$levelname][NemesisMITM]:",
        levelThreshold = lvlInfo)
    var fileLog = newFileLogger("errors.log", levelThreshold=lvlError)
    addHandler(stdout)
    addHandler(fileLog)

proc start(port: int) = 
    let server = newAsyncSocket(buffered=false)
    server.setSockOpt(OptReuseAddr, true) 
    server.bindAddr(Port(port), "127.0.0.1")
    try:
        server.listen()
        log(lvlInfo, "STARTED")
        var connections = 0
        while true:
           var client = newAsyncSocket(buffered=false)
           client = waitFor server.accept()
           log(lvlDebug, " Connections: " & $connections)
           asyncCheck processClient(client) 
           connections += 1
    except:
       log(lvlError, "[start] " & getCurrentExceptionMsg())
    finally:
        server.close()

when isMainModule:
    setupLogging()
    log(lvlInfo, "STARTING")
    if not dirExists("certs"):
        log(lvlInfo,"Root CA not found, generating :: certs/ca.pem")
        log(lvlInfo,"Do not forget to import/use this CA !")
        if not createCA():
            log(lvlError,"[!] Error while creating CA.")
            quit(QuitFailure)
    try:
        start(8081)
    except:
        log(lvlError, "[start] " & getCurrentExceptionMsg())
