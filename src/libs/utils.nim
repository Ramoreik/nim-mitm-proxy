import std/[osproc, strformat]

proc execCmdWrap*(cmd: string): bool =
    if execCmd(cmd) != 0:
        echo "[!] An error occured\n"
        echo fmt"[?] {cmd}"
        false
    else:
        true
