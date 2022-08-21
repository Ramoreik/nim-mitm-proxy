import std/[re, strutils, strformat, asyncnet, os,
        asyncdispatch, tables, net, osproc]
import libs/[parser, reader, certman]
import cligen, asyncthreadpool

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


proc tunnel(client: AsyncSocket, remote: AsyncSocket) {.async.} = 
    proc clientHasData() {.async.} =
            try:
                while not client.isClosed and not remote.isClosed:
                    let data = client.recv(4096)
                    let future_data = await data.withTimeout(5000)
                    if future_data and data.read.len() != 0 and not remote.isClosed:
                        echo "[?] Client Tunnel iteration."

                        #echo "RAW REQUEST: \n" & data.read
                        await remote.send(data.read)
                    else:
                        break
            except:
                echo getCurrentExceptionMsg()
            finally:
                client.close()
    proc remoteHasData() {.async.} =
        try:
            while not remote.isClosed and not client.isClosed:
                echo "[?] Remote RECV"
                let data = remote.recv(4096)
                let future_data = await data.withTimeout(5000)
                if future_data and data.read.len() != 0 and not client.isClosed:
                    echo "[?] Remote Tunnel SENDING."
                    #echo "RAW RESPONSE: \n" & data.read
                    let fut_send = client.send(data.read)
                    yield fut_send 
                    echo "[?] Remote Tunnel SENT"
                    if fut_send.failed:
                        echo "[!] Send FAILED !"
                else:
                    break
        except:
            echo getCurrentExceptionMsg()
        finally: 
            remote.close()
    try:
        asyncCheck clientHasData()
        asyncCheck remoteHasData()
    except:
        echo getCurrentExceptionMsg()

# - - - - - - - - - - - - - - - - - -
#  Server + client handling
# - - - - - - - - - - - - - - - - - -
proc processClient(client: AsyncSocket) {.async.} =
    let proxy_req = await readHTTPRequest(client)
    var headers = parseHeaders(proxy_req.headers)
    var requestline = 
        if headers.hasKey("requestline"): headers["requestline"].split(" ") 
        else: @[""]
    if requestline == @[""]:
        echo "[!] Invalid requestline, terminating connection."
        echo fmt"[?] {headers}"
        await client.send(BAD_REQUEST)
        client.close()
        return

    var host_info = parseProxyHost(requestline[1])
    if host_info.host == "":
        echo "[!] Invalid host, terminating connection."
        await client.send(BAD_REQUEST)
        client.close()
        return

    if requestline[0] != "CONNECT":
        if host_info.proto == "http":
            echo fmt"[+] Proxying | {client.getPeerAddr()[0]} ->> http://{host_info.host}:{host_info.port}{host_info.route}"
            try:
                # connect to remote
                let remote = newAsyncSocket(buffered=false)
                await remote.connect(host_info.host, Port(host_info.port))

                # modify host in requestline
                requestline[1] = host_info.route
                headers["requestline"] = join(requestline, " ")

                # construct request for remote
                var req = proxyHeaders(headers) & proxy_req.body

                # parse response information
                var res_info = await remote.sendRawRequest(req)
                var res: string
                if headers.hasKey("Content-Length"):
                    res = res_info.headers & res_info.body
                else:
                    res = res_info.headers

                await client.send(res_info.headers & res_info.body)
                client.close()
                remote.close()
            except:
                echo "[!] Could not resolve remote, terminating connection."
                await client.send(NOT_FOUND)
                client.close()
        else:
            echo "[!] This proxy method is only for HTTP."
            await client.send(BAD_REQUEST)
            client.close()
    else:
        echo fmt"[+] MITM Tunneling | {client.getPeerAddr()[0]} ->> {host_info.host}:{host_info.port} "
        try: 

            let host = host_info.host
            if not handleHostCertificate(host):
                echo fmt"[!] Error occured while generating certificate for {host}"
                await client.send(BAD_REQUEST)

            # connect to remote and negotiate SSL
            let remote = newAsyncSocket(buffered=false)
            let remote_ctx = newContext(verifyMode = CVerifyNone)
            wrapSocket(remote_ctx, remote)
            await remote.connect(host, Port(host_info.port))

            # confirm tunneling with client
            await client.send(OK)

            # wrap with my own SSL context
            let ctx = getMITMContext(host)
            wrapConnectedSocket(ctx, client, handshakeAsServer, hostname = host)

            # tunnel the two sockets
            try:
                await tunnel(client, remote)
            except:
                echo "[!] Tunnel Crashed."
                echo getCurrentExceptionMsg()
        except:
            echo "[!] Could not resolve remote, terminating connection."
            await client.send(NOT_FOUND)
            client.close()

proc start(port: int) {.async.} = 
    let server = newAsyncSocket(buffered=false)
    server.setSockOpt(OptReuseAddr, true) 
    server.bindAddr(Port(port), "127.0.0.1")

    try:
        server.listen()
        while true:
           var client = newAsyncSocket(buffered=false)
           client = await server.accept()
           try:
               asyncCheck processClient(client) 
           except:
               echo "processing client crashed"
               echo getCurrentExceptionMsg()
    except:
        echo "[!] Unknown Error happened."
    finally:
        server.close()

when isMainModule:
    if not dirExists("certs"):
        echo "[!] Root CA not found, generating :: certs/ca.pem"
        echo "[!] Do not forget to import/use this CA !"
        if not createCA():
            echo "[!] Error while creating CA."
            quit(QuitFailure)
    try:
        asyncCheck start(8081)
    except:
        echo getCurrentExceptionMsg()
    runForever()
