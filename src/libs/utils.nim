import std/[osproc, strformat, 
            logging, os, times]

let INTERACTIONS_D = "interactions"


proc execCmdWrap*(cmd: string): bool =
    ## Wrapper proc to catch errors when executing OS commands.
    ## Should add sanitization here.
    log(lvlDebug, fmt"[execCmdWrap] running {cmd}")
    if execCmd(cmd) != 0:
        log(lvlError, "[execCmdWrap] An error occured\n")
        false
    else:
        true


proc saveInteraction*(host: string, port: int, 
                     interaction: tuple[src_data: string, dst_data: string]): bool =
    ## Saves an interaction to disk.
    ## Still very much a WIP, 
    # will potentially not use this later and favor a DB of some kind.
    let dirname = joinPath(INTERACTIONS_D, fmt"{host}-{port}")
    if not dirExists(INTERACTIONS_D): createDir(INTERACTIONS_D)
    if not dirExists(dirname): createDir(dirname)
    let dt = now()
    let timestamp = dt.format("yyyy-MM-dd-HH:mm:ss")
    let msg = interaction[0] & "\n---- SNIP ----\n" & interaction[1]
    try:
        var f = open(joinPath(dirname, timestamp), fmWrite)
        f.write(msg)
        f.close()
    except: return false
    true
