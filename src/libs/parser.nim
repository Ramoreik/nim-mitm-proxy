import std/[re, tables, strutils, logging, strformat]

let HEADER_REGEX = re"^([A-Za-z0-9-]*):(.*)$"
let REQUESTLINE_REGEX = re"([A-Z]{1,511}) ([^ \n\t]*) HTTP\/[0-9]\.[0-9]"
let RESPONSELINE_REGEX = re"HTTP/[0-9]\.[0-9] [0-9]{3} [A-Z ]*"
let PROXY_HOST_REGEX = re"(http:\/\/|https:\/\/)?([^/<>:""'\|?*]*):?([0-9]{1,5})?(\/[^\n\t]*)?"
let CONTENT_TYPE = re"Content-Type: ([^\r\n]*\r\n)"
let ACCEPT_ENCODING = re"Accept-Encoding: ([^\r\n]*)\r\n"
let TRANSFER_ENCODING = re"Transfer-Encoding: ([^\r\n]*)\r\n"
let CONTENT_LENGTH = re"Content-Length: ([^\r\n]*)\r\n"
let HTTP_PROTO = "http"
let HTTPS_PROTO = "https"
let PROXY_HEADERS = ["Proxy-Connection", "requestline", "responseline"]
let ALLOWED_DATA_TYPES = ["text", "application", "multipart", "model", "message"]


proc parseHeaders*(headers: string): Table[string, string] =
    ## Maps a raw header section to a Table.
    ## Inserts the requestline and responseline headers.
    ## Returns the populated table.
    for header in headers.splitLines():
        var matches: array[2, string]
        if re.find(header, HEADER_REGEX, matches) != -1:
            result[matches[0].strip()] = matches[1].strip()
        elif re.find(header, REQUESTLINE_REGEX, matches) != -1:
            result["requestline"] = header 
        elif re.find(header, RESPONSELINE_REGEX, matches) != -1:
            result["responseline"] = header


proc parseProxyHost*(host: string): tuple[proto: string, host: string,
                                          port: int, route: string] = 
    ## Parse the host that we are asked to proxy to.
    ## Returns a tuple representing each part of the host provided.
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


proc proxyHeaders*(headers: Table[string, string]): string =
    ## Create the header section for a raw request by using the provided table, 
    ## returns string.
    ## Will remove headers pertaining to the proxy, such headers are contained in PROXY_HEADERS.
    if headers.hasKey("requestline"):
        result = join([headers["requestline"], result], "\r\n")
    elif headers.hasKey("responseline"):
        result = join([headers["responseline"], result], "\r\n")
    for k, v in headers.pairs:
        if not PROXY_HEADERS.contains(k) :
            result = result & join([k, v], ": ") & "\r\n"
    result = result & "\r\n"


proc parseRequest*(request: string, cid: string): seq[tuple[headers: string, body: string]] =
    ## Attempts to parse an HTTP stream correctly.
    ## Very scuffed.
    ## Should refactor + relocate most of this code.
    let baseLog = fmt"[{cid}][parseRequest]"
    var requests: seq[tuple[headers: string, body: string]]
    log(lvlDebug, 
        baseLog & fmt"[REQ_LENGTH][{$request.high()}]")

    # Iterate over the string and parse request/responses while doing so.
    # I should use a StringStream for this.
    var index: int
    while index < len(request) and index != -1:
        var rid = len(requests) + 1
        var headers: Table[string, string]
        var body = "\r\n\r\n"
        let start_index = index
        index = request.find("\r\n\r\n", start=start_index)
        if index != -1:
            # the -1's are to adjust for 0 notation of sequences.
            # exclude \r\n\r\n
            index += 4

            log(lvlDebug, 
                baseLog & fmt"[{rid}][START_INDEX][{$start_index}]")
            log(lvlDebug, 
                baseLog & fmt"[{rid}][INDEX][{$index}]")
            headers = parseHeaders(request[start_index .. index - 1])
            if not (headers.hasKey("requestline") or headers.hasKey("responseline")):
                    log(lvlError, 
                        baseLog & fmt"[{rid}][EMPTY HEADERS !]")
            if headers.hasKey("Content-Length"):
                let contentLength = parseInt(headers["Content-Length"].strip())
                body = request[index .. index + contentLength - 1]
                log(lvlDebug, 
                    baseLog & fmt"[{rid}][Content-Length][{contentLength}]")
                index = index + contentLength 
        let interaction = (headers: proxyHeaders(headers), body: body)
        requests.add(interaction)
    return requests


proc removeEncoding*(req: string): string =
    ## This completely removes any Transfer-Encoding headers from the given request
    return req.replace(re"Transfer-Encoding: .*\r\n", "")


proc decode() =
    ## proc to decode the data from the appropriate transfer-encoding
    ## -- wip
    # elif headers.hasKey("transfer-encoding") or headers.hasKey("Transfer-Encoding"):
    #     log(lvlDebug, 
    #         baseLog & fmt"[{rid}][CHUNKED ENCODING]")
    #     ## Since i remove the Accept-Encoding header, this should only be chunked.
    #     ## But I will add validation.
    #     ## Read the chunks and populate the body.
    #     var chunks: seq[string]
    #     while true:
    #         var chunk_start = request.find("\r\n", start=index)
    #         if chunk_start == -1:
    #             break

    #         log(lvlDebug, 
    #             baseLog & fmt"[{rid}][CHUNK_START][{chunk_start}]")
    #         var hex_chunk_size = request[index .. chunk_start - 1]

    #         var chunk_size: int
    #         try:
    #             chunk_size = fromHex[int](hex_chunk_size)
    #         except:
    #             chunk_size = 0

    #         ## +2 to skip the \r\n after the chunk length
    #         ## -1 for 0 notation
    #         chunks.add(request[chunk_start + 2 .. chunk_start + 2 + chunk_size - 1])
    #         log(lvlDebug, 
    #             baseLog & fmt"[{rid}][CHUNKED][{chunk_size}]")

    #         ## +4 to skip \r\n twice
    #         index = chunk_start + chunk_size + 4
    #         if chunk_size == 0:
    #             break

    #     body = join(chunks, "")


proc excludeData*(req: string): bool = 
    ## My Half-assed attempt at filtering out data.
    ## Since the sockets seem to be reused for multiple request, It's making it hard.
    ## Disable content-type checking for now, using content-length only.
    var content_length = @[""]
    if find(req, CONTENT_LENGTH, content_length) != -1:
        log(lvlDebug, "Content-Length: " & content_length)
        if parseInt(content_length[0]) > 1000000:
            log(lvlDebug, "EXCLUDED: Content-Length: " & content_length)
            return true
    else:
        return false

