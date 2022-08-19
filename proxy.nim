import std/[re, strutils, strformat, asyncnet, os,
        asyncdispatch, tables, net, osproc]

let BAD_REQUEST = "HTTP/1.1 400 BAD REQUEST\r\nConnection: close\r\n\r\n"
let OK = "HTTP/1.1 200 OK\r\n\r\n"
let NOT_IMPLEMENTED = "HTTP/1.1 501 NOT IMPLEMENTED\r\nConnection: close\r\n\r\n"
let NOT_FOUND = "HTTP/1.1 404 NOT FOUND\r\nConnection: close\r\n\r\n"

let HEADER_REGEX = re"^([A-Za-z0-9-]*):(.*)$"
let REQUESTLINE_REGEX = re"([A-Z]{1,511}) ([^ \n\t]*) HTTP\/[0-9]\.[0-9]"
let RESPONSELINE_REGEX = re"HTTP/[0-9]\.[0-9] [0-9]{3} [A-Z ]*"
let PROXY_HOST_REGEX = re"(http:\/\/|https:\/\/)?([^/<>:""'\|?*]*):?([0-9]{1,5})?(\/[^\n\t]*)?"
let VALID_HOST = re"^[^']{2,63}"

let HTTP_PROTO = "http"
let HTTPS_PROTO = "https"

let PROXY_HEADERS = ["Proxy-Connection", "requestline", "responseline"]
let CONFIG_D = "config"
let CERTS_D = "certs"
let CA_KEY = CERTS_D & "/ca.key.pem"
let CA_FILE = CERTS_D & "/ca.pem"
let TEMPLATE_FILE = CONFIG_D & "/template.cnf"

# inspiration taken from: https://xmonader.github.io/nimdays/day15_tcprouter.html
# by inspiration I mean it saved me hours of trial and error since i'm dumb.

# This project is to learn the concepts involved in HTTP/HTTPS proxying, Websockets proxying and SOCKS. 
# Next step - negotiate SSL between the proxy and client to be able to read traffic passing through.
# a bit like : https://mitmproxy.org/

# to MITM, i have to place myself as the remote client, when im tunnelling.
# meaning:
# 1 - I wrap the socket intented for the remote server with my ssl context
# 2 - I start another socket and i negotiate ssl to the actual target
# 3 - I tunnel the two and I can read the data in the tunnel.

# For this to work I also have to generate certs on the fly
# see genca.sh and create-cert.sh for now.
# will clean this up soon.

# TODO: Reimplement the certificate generation without bash
# TODO: Add better, granular error handling
# TODO: Try to find edgecases in which the proxy fails.

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
#   Certificate handling
# - - - - - - - - - - - - - - - - - -
proc execCmdWrap(cmd: string): bool =
    if execCmd(cmd) != 0:
        echo "[!] An error occured\n"
        echo fmt"[?] {cmd}"
        false
    else:
        true

proc createCA(): bool =
    let openssl = findExe("openssl")
    let chmod = findExe("chmod")

    if not dirExists(CERTS_D): createDir(CERTS_D)

    echo fmt"[*] Creating root key :: " & CA_KEY
    if not execCmdWrap(
           openssl & fmt" genrsa -out '{CA_KEY}' 2048"):
        return false

    if not execCmdWrap(
            chmod & fmt" 400 '{CA_KEY}'"):
        return false

    echo fmt"[*] Creating root CA :: {CA_FILE}"
    if not execCmdWrap(
            fmt"""
                {openssl} req -new -x509 \
                -subj '/CN=NemesisMITM' \
                -extensions v3_ca \
                -days 3650 \
                -key '{CA_KEY}' \
                -sha256 \
                -out '{CA_FILE}' \
                -config '{TEMPLATE_FILE}'"""): 
        return false
    true

proc generateHostCertificate(host: string): bool =
    let openssl = findExe("openssl")
    let sed = findExe("sed")
    let server_d = CERTS_D & "/" & host
    let key_file = fmt"{server_d}/{host}.key.pem"
    let cert_file = fmt"{server_d}/{host}.crt"
    let csr_file = fmt"{server_d}/{host}.csr"
    let cnf_file = fmt"{server_d}/{host}.cnf"
    let srl_file = fmt"{server_d}/{host}.srl"

    if not match(host, VALID_HOST): 
        echo "[!] Invalid host provided."
        return false

    if not dirExists(server_d): createDir(server_d)

    echo "[*] Creating key for: " & host
    if not execCmdWrap(
            openssl & fmt" genrsa -out '{key_file}'"): 
        return false

    if fileExists(TEMPLATE_FILE):
        var config = open(TEMPLATE_FILE).readAll()
        config = config.replace("{{domain}}", host) 
        var f = open(cnf_file, fmWrite)
        f.write(config)
        f.close()

    echo "[*] Creating csr for: " & host
    if not execCmdWrap(
            fmt"""
            {openssl} req -subj '/CN={host}' \
            -extensions v3_req \
            -sha256 -new \
            -key {key_file} \
            -out {csr_file} \
            -config {cnf_file}
            """):
        return false

    echo "[*] Creating cert for: " & host 
    if not execCmdWrap(
            fmt"""
            openssl x509 -req -extensions v3_req \
              -days 3650 -sha256 \
              -in '{csr_file}' \
              -CA '{CA_FILE}' \
              -CAkey '{CA_KEY}' \
              -CAcreateserial \
              -CAserial '{srl_file}' \
              -out "{cert_file}" \
              -extfile "{cnf_file}"            
            """):
        return false
    true


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
                if fut and data.read.len() != 0 and not remote.isClosed:
                    echo "RAW REQUEST: \n" & data.read
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
                if fut and data.read.len() != 0 and not client.isClosed:
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
        echo fmt"[+] MITM Tunneling | {client.getPeerAddr()[0]} ->> {host_info.host}:{host_info.port} "
        try: 

            let host = host_info.host
            let keyfile = joinPath(CERTS_D, host, host & ".key.pem")
            let certfile = joinPath(CERTS_D, host, host & ".crt")

            # generate cert for remote if it doesn't exist.
            if not fileExists(keyfile) or not fileExists(certfile):
                if not generateHostCertificate(host):
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
            let ctx = newContext(keyFile = keyfile, certFile = certfile)
            wrapConnectedSocket(ctx, client, handshakeAsServer, hostname = host)

            # tunnel the two
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
    try:
        server.listen()
        while true:
           client = await server.accept()
           asyncCheck processClient(client) 
    finally:
        server.close()


when isMainModule:
    if not dirExists("certs"):
        echo "[!] Root CA not found, generating :: certs/ca.pem"
        echo "[!] Do not forget to import/use this CA !"
        if not createCA():
            echo "[!] Error while creating CA."
            quit(QuitFailure)

    asyncCheck start(8081)
    runForever()
