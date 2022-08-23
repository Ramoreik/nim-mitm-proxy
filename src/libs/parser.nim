import std/[re, tables, strutils, logging]

let HEADER_REGEX = re"^([A-Za-z0-9-]*):(.*)$"
let REQUESTLINE_REGEX = re"([A-Z]{1,511}) ([^ \n\t]*) HTTP\/[0-9]\.[0-9]"
let RESPONSELINE_REGEX = re"HTTP/[0-9]\.[0-9] [0-9]{3} [A-Z ]*"
let PROXY_HOST_REGEX = re"(http:\/\/|https:\/\/)?([^/<>:""'\|?*]*):?([0-9]{1,5})?(\/[^\n\t]*)?"
let CONTENT_TYPE = re"Content-Type: ([^\r\n]*\r\n)"
let ACCEPT_ENCODING = re"Accept-Encoding: ([^\r\n]*)\r\n"
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


proc removeEncoding*(req: string): string =
    ## This simply removes any encodings such as gzip.
    ## This is temporary, I will probable try decode gzip requests eventually.
    var encoding = @[""]
    if find(req, ACCEPT_ENCODING, encoding) != -1:
        if len(encoding) > 0:
            return req.replace(encoding[0], "")
    return req


proc excludeData*(req: string): bool = 
    ## My Half-assed attempt at filtering out data.
    ## Since the sockets seem to be reused for multiple request, It's making it hard.
    ## Disable content-type checking for now, using content-length only.
    ## TEMPORARY DEACTIVATION
    # var content_type = @[""]
    # if find(req, CONTENT_TYPE, content_type) != -1:
    #     log(lvlDebug, "Content-Type: " & content_type)
    #     if content_type[0].split("/")[0] in ALLOWED_DATA_TYPES:
    #         return false
    #     else:
    #         log(lvlDebug, "EXCLUDED: Content-Type: " & content_type)
    #         return true
    var content_length = @[""]
    if find(req, CONTENT_LENGTH, content_length) != -1:
        log(lvlDebug, "Content-Length: " & content_length)
        if parseInt(content_length[0]) > 1000000:
            log(lvlDebug, "EXCLUDED: Content-Length: " & content_length)
            return true
    else:
        return false
