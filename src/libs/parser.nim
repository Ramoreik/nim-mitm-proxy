import std/[re, tables, strutils, logging]

let HEADER_REGEX = re"^([A-Za-z0-9-]*):(.*)$"
let REQUESTLINE_REGEX = re"([A-Z]{1,511}) ([^ \n\t]*) HTTP\/[0-9]\.[0-9]"
let RESPONSELINE_REGEX = re"HTTP/[0-9]\.[0-9] [0-9]{3} [A-Z ]*"
let PROXY_HOST_REGEX = re"(http:\/\/|https:\/\/)?([^/<>:""'\|?*]*):?([0-9]{1,5})?(\/[^\n\t]*)?"
let CONTENT_TYPE = re"Content-Type: ([^\r\n]*)\r\n"
let HTTP_PROTO = "http"
let HTTPS_PROTO = "https"
let PROXY_HEADERS = ["Proxy-Connection", "requestline", "responseline"]
let ALLOWED_DATA_TYPES = ["text", "application", "multipart", "model", "message"]


proc parseHeaders*(headers: string): Table[string, string] =
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
    if headers.hasKey("requestline"):
        result = join([headers["requestline"], result], "\r\n")
    elif headers.hasKey("responseline"):
        result = join([headers["responseline"], result], "\r\n")
    for k, v in headers.pairs:
        if not PROXY_HEADERS.contains(k) :
            result = result & join([k, v], ": ") & "\r\n"
    result = result & "\r\n"

# filter by checking content-type of request.
proc excludeData*(req: string): bool = 
    var matches = @[""]
    if find(req, CONTENT_TYPE, matches) != -1:
        if matches[0].split("/")[0] in ALLOWED_DATA_TYPES:
            echo "ALLOWED"
            return false
        else:
            return true
    else:
        return false
