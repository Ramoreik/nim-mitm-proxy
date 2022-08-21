import std/[osproc, strformat, logging]

proc execCmdWrap*(cmd: string): bool =
    log(lvlDebug, fmt"[execCmdWrap] running {cmd}")
    if execCmd(cmd) != 0:
        log(lvlError, "[execCmdWrap] An error occured\n")
        false
    else:
        true
