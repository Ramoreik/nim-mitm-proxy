import std/[asyncdispatch, asyncnet, strutils, strformat, logging,
            tables]
import parser


proc readHeaders*(socket: AsyncSocket): Future[string] {.async.} = 
    ## Reads the header section of a request/response from the given socket.
    ## Returns raw headers
    while true:
        var line: string
        line = await socket.recvLine()
        if line == "\r\n" or line == "":
            break
        result = result & line & "\r\n"


proc readBody*(socket: AsyncSocket, size: int): Future[string] {.async.} = 
    ## Reads the body section of a request/response from the given socket.
    ## Returns raw body
    var chunk_size = 4096
    while result.len() != size:
        let chunk = waitFor socket.recv(chunk_size)
        result = result & chunk


proc readHTTPRequest*(socket: AsyncSocket, body: bool = true ): 
        Future[tuple[headers: string, body: string]] {.async.} =
    ## Reads a full HTTP request/response from the given socket.
    ## returns a tuple representing the headers and body of the request/response.
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


proc parseRequest*(request: string, cid: string): seq[tuple[headers: string, body: string]] =
    ## Attempts to parse an HTTP stream correctly.
    ## Very scuffed.
    var requests: seq[tuple[headers: string, body: string]]
    log(lvlDebug, fmt"[{cid}][parseRequest][REQ_LENGTH][{$request.high()}]")

    # Iterate over the string and parse request/responses while doing so.
    # I should use a StringStream for this.
    var index: int
    while index < len(request) and index != -1:
        var headers: Table[string, string]
        var body = "\r\n\r\n"
        let start_index = index
        index = request.find("\r\n\r\n", start=start_index)
        if index != -1:
            # the -1's are to adjust for 0 notation of sequences.
            # exclude \r\n\r\n
            index += 4

            log(lvlDebug, fmt"[{cid}][parseRequest][START_INDEX][{$start_index}]")
            log(lvlDebug, fmt"[{cid}][parseRequest][INDEX][{$index}]")
            headers = parseHeaders(request[start_index .. index - 1])
            if not (headers.hasKey("requestline") or headers.hasKey("responseline")):
                    log(lvlError, "EMPTY HEADERS !")


            log(lvlDebug, fmt"[{cid}][parseRequest][INDEX][{index - 1}]")
            if headers.hasKey("Content-Length"):
                let contentLength = parseInt(headers["Content-Length"].strip())
                body = request[index .. index + contentLength - 1]
                # log(lvlDebug, fmt"[parseRequest][parseRequest][BODY][{$body}]")
                log(lvlDebug, fmt"[{cid}][Content-Length][{contentLength}]")
                index = index + contentLength 

            elif headers.hasKey("transfer-encoding"):
                ## Read the chunks and populate the body.
                var chunks: seq[string]
                while true:
                    var chunk_start = request.find("\r\n", start=index)
                    log(lvlDebug, fmt"[{cid}][CHUNK_START][{chunk_start}]")
                    var hex_chunk_size = request[index .. chunk_start - 1]
                    var chunk_size = fromHex[int](hex_chunk_size)

                    ## +2 to skip the \r\n after the chunk length
                    ## -1 for 0 notation
                    chunks.add(request[chunk_start + 2 .. chunk_start + 2 + chunk_size - 1])
                    log(lvlDebug, fmt"[{cid}][parseRequest][CHUNKED][{chunk_size}]")

                    ## +4 to skip \r\n twice
                    index = chunk_start + chunk_size + 4
                    if chunk_size == 0:
                        break

                body = join(chunks, "")
        let interaction = (headers: proxyHeaders(headers), body: body)
        requests.add(interaction)
    return requests
