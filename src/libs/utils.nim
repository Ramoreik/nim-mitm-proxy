import std/[osproc, strformat, logging, os, times]

let INTERACTIONS_D = "interactions"

proc execCmdWrap*(cmd: string): bool =
    log(lvlDebug, fmt"[execCmdWrap] running {cmd}")
    if execCmd(cmd) != 0:
        log(lvlError, "[execCmdWrap] An error occured\n")
        false
    else:
        true

proc setupLogging*() = 
    var stdout = newConsoleLogger(
        fmtStr = "[$time][$levelname][NemesisMITM]:",
        levelThreshold = lvlInfo)
    var fileLog = newFileLogger("errors.log", levelThreshold=lvlError)
    addHandler(stdout)
    addHandler(fileLog)

proc saveInteraction*(host: string, port: int, 
                     interaction: tuple[src_data: string, dst_data: string]): bool =

    let dirname = joinPath(INTERACTIONS_D, fmt"{host}-{port}")
    if not dirExists(INTERACTIONS_D): createDir(INTERACTIONS_D)
    if not dirExists(dirname): createDir(dirname)
    let dt = now()
    let timestamp = dt.format("yyyy-MM-dd-HH:mm:ss")
    let msg = "-- REQUEST --\n" & 
              interaction[0] & 
              "-- RESPONSE --\n" &
              interaction[1]
    try:
        var f = open(joinPath(dirname, timestamp), fmWrite)
        f.write(msg)
        f.close()
    except: return false
    true

