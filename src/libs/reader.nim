import std/[asyncdispatch, asyncnet, strutils, tables]
import parser


proc readHeaders*(socket: AsyncSocket): Future[string] {.async.} = 
    while true:
        var line: string
        line = await socket.recvLine()
        if line == "\r\n" or line == "":
            break
        result = result & line & "\r\n"

proc readBody*(socket: AsyncSocket, size: int): Future[string] {.async.} = 
    var chunk_size = 4096
    while result.len() != size:
        let chunk = waitFor socket.recv(chunk_size)
        result = result & chunk

proc readHTTPRequest*(socket: AsyncSocket, body: bool = true ): 
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

