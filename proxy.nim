import std/[re, strutils, strformat, asyncnet, asyncdispatch, tables]

let BAD_REQUEST = "HTTP/1.1 400 BAD REQUEST\r\nConnection: close\r\n\r\n"
let OK = "HTTP/1.1 200 OK\r\n\r\n"
let NOT_IMPLEMENTED = "HTTP/1.1 501 NOT IMPLEMENTED\r\nConnection: close\r\n\r\n"
let NOT_FOUND = "HTTP/1.1 404 NOT FOUND\r\nConnection: close\r\n\r\n"

let HEADER_REGEX = re"^([A-Za-z0-9-]*):(.*)$"
let REQUESTLINE_REGEX = re"([A-Z]{1,511}) ([^ \n\t]*) HTTP\/[0-9]\.[0-9]"
let RESPONSELINE_REGEX = re"HTTP/[0-9]\.[0-9] [0-9]{3} [A-Z ]*"
let PROXY_HOST_REGEX = re"(http:\/\/|https:\/\/)?([^/<>:""'\|?*]*):?([0-9]{1,5})?(\/[^\n\t]*)?"

let HTTP_PROTO = "http"
let HTTPS_PROTO = "https"

let PROXY_HEADERS = ["Proxy-Connection"]
# inspiration taken from: https://xmonader.github.io/nimdays/day15_tcprouter.html
# by inspiration I mean it saved me hours of trial and error since i'm dumb.

# This project is to learn the concepts involved in HTTP/HTTPS proxying, Websockets proxying and SOCKS. 
# Next step - negotiate SSL between the proxy and client to be able to read traffic passing through.
# a bit like : https://mitmproxy.org/

# - - - - - - - - - - - - - - - - - -
# PARSING + HEADER MODIFICATION
# - - - - - - - - - - - - - - - - - -
proc parseHeaders(headers: string): Table[string, string] =
    for header in headers.splitLines():
        var matches: array[2, string]
        if re.find(header, HEADER_REGEX, matches) != -1:
            result[matches[0].strip()] = matches[1].strip()
        elif re.find(header, REQUESTLINE_REGEX, matches) != -1:
            result["requestline"] = header 
        elif re.find(header, RESPONSELINE_REGEX, matches) != -1:
            result["responseline"] = header

proc parseProxyHost(host: string): 
        tuple[proto: string, host: string, port: int, route: string] = 
    var matches: array[4, string]
    if re.find(host, PROXY_HOST_REGEX, matches) != -1:
        let host = matches[1]
        let proto = 
            if matches[0] == "" or matches[2] == "443": HTTPS_PROTO 
            else: HTTP_PROTO
        let route = 
            if matches[3] == "": "/" 
            else: matches[3]
        let port = 
            if matches[2] == "" and proto == HTTPS_PROTO: 443
            elif matches[2] == "" and proto == HTTP_PROTO: 80
            else: parseInt(matches[2])
        result = (proto: proto, host: host, port: port, route: route)
    else:
        result = (proto: "", host: "", port: 80, route: "")

proc proxyHeaders(headers: Table[string, string]): string =
    if headers.hasKey("requestline"):
        result = join([headers["requestline"], result], "\r\n")
    elif headers.hasKey("responseline"):
        result = join([headers["responseline"], result], "\r\n")
    for k, v in headers.pairs:
        if not PROXY_HEADERS.contains(k) :
            result = result & join([k, v], ": ") & "\r\n"
    result = result & "\r\n"

# - - - - - - - - - - - - - - - - - -
# READING REQUESTS
# - - - - - - - - - - - - - - - - - -
proc readHeaders(socket: AsyncSocket): Future[string] {.async.} = 
    while true:
        var line: string
        line = await socket.recvLine()
        if line == "\r\n" or line == "":
            break
        result = result & line & "\r\n"

proc readBody(socket: AsyncSocket, size: int): Future[string] {.async.} = 
    var chunk_size = 4096
    while result.len() != size:
        let chunk = waitFor socket.recv(chunk_size)
        result = result & chunk

proc readHTTPRequest(socket: AsyncSocket, body: bool = true ): 
        Future[tuple[headers: string, body: string]] {.async.} =
    let raw_headers = await readHeaders(socket)
    let headers = parseHeaders(raw_headers)
    if body:
        if headers.hasKey("Content-Length"):
            let contentLength = parseInt(headers["Content-Length"].strip())
            var body = await readBody(socket, contentLength)
            result = (headers: proxyHeaders(headers), body: body & "\r\n\r\n")
        else:
            result = (headers: proxyHeaders(headers), body: "\r\n\r\n")
    else:
        result = (headers: proxyHeaders(headers), body: "\r\n\r\n")

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
        while not client.isClosed and not remote.isClosed:
            try:
                let data = client.recv(4096)
                let fut = await data.withTimeout(5000)
                if fut and data.read.len() != 0:
                    await remote.send(data.read)
                else:
                    break
            except:
                echo getCurrentExceptionMsg()
        client.close()

    proc remoteHasData() {.async.} =
        while not remote.isClosed and not client.isClosed:
            try:
                let data = remote.recv(4096)
                let fut = await data.withTimeout(5000)
                if fut and data.read.len() != 0:
                    await client.send(data.read)
                else:
                    break
            except:
                echo getCurrentExceptionMsg()
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
        echo fmt"[+] Tunneling | {client.getPeerAddr()[0]} ->> {host_info.host}:{host_info.port} "
        try: 
            # connect to remote
            let remote = newAsyncSocket(buffered=false)
            await remote.connect(host_info.host, Port(host_info.port))
            # confirm tunneling with client
            await client.send(OK)
            asyncCheck tunnel(client, remote)
        except:
            echo "[!] Could not resolve remote, terminating connection."
            await client.send(NOT_FOUND)
            client.close()

proc start(port: int) {.async.} = 
    let server = newAsyncSocket(buffered=false)
    server.setSockOpt(OptReuseAddr, true) 
    server.bindAddr(Port(port), "127.0.0.1")
    var client = newAsyncSocket(buffered=false)
    client.close()
    try:
        server.listen()
        while true:
           client = await server.accept()
           asyncCheck processClient(client) 
    finally:
        server.close()

when isMainModule:
    asyncCheck start(8081)
    runForever()
