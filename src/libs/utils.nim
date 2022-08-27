import std/[osproc, strformat,
            logging, os, times]

let INTERACTIONS_D = "interactions"


proc execCmdWrap*(cmd: string): bool =
    ## Wrapper proc to catch errors when executing OS commands.
    ## Should add sanitization here.
    log(lvlDebug, fmt"[execCmdWrap] running {cmd}.")
    if execCmd(cmd) != 0:
        log(lvlError, "[execCmdWrap] An error occured.")
        false
    else:
        true


proc saveInteraction*(host: string, port: int, cid: string,
                     interaction: seq[tuple[headers: string, body: string]]): bool =
    ## Saves an interaction to disk.
    ## Still very much a WIP, 
    # will potentially not use this later and favor a DB of some kind.
    log(lvlDebug, 
        fmt"[{cid}][saveInteraction][Number of Requests][{len(interaction)}]")
    let dirname = joinPath(INTERACTIONS_D, fmt"{host}-{port}")
    if not dirExists(INTERACTIONS_D): createDir(INTERACTIONS_D)
    if not dirExists(dirname): createDir(dirname)
    let dt = now()
    let timestamp = dt.format("yyyy-MM-dd-HH:mm:ss")
    for i in 1 .. interaction.high():
        if i.mod(2) != 0:
            let req = interaction[i - 1]
            let res = interaction[i]
            var msg = req.headers & req.body & "\n---- SNIP ----\n" & res.headers & res.body 
            try:
                var f = open(
                    joinPath(dirname, fmt"{cid}-interaction-{timestamp}-{(i+1)/2}"),
                    fmWrite)
                f.write(msg)
                f.close()
            except: return false
    true
