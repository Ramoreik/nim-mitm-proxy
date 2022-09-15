import std/[osproc, strformat,
            logging, os, times, db_sqlite]

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

proc initDb(): bool =
    try:
        let db = open("interactions.db", "", "", "")
        db.exec(sql"""
            CREATE TABLE interaction (
                    id TEXT,
                    host TEXT,
                    port INTERGER,
                    request BLOB,
                    response BLOB,
                    timestamp TEXT
                )
            """)
        db.close()
    except: return false
    true


proc saveInteraction*(host: string, port: int, cid: string,
                     interaction: seq[tuple[headers: string, body: string]]): bool =
    ## Saves an interaction to disk.
    ## Still very much a WIP, 
    # will potentially not use this later and favor a DB of some kind.
    log(lvlDebug, 
        fmt"[{cid}][saveInteraction][Number of Requests][{len(interaction)}]")
    if not fileExists("interactions.db"): 
        if not initDb(): 
            log(lvlError, fmt"[{cid}][saveInteraction] Unable to create database.")
            return false
    let dt = now()
    let timestamp = dt.format("yyyy-MM-dd-HH:mm:ss")
    for i in 1 .. interaction.high():
        if i.mod(2) != 0:
            let req = interaction[i - 1].headers & interaction[i - 1].body
            let res = interaction[i].headers & interaction[i].body
            try:
                let db = open("interactions.db", "", "", "")
                db.exec(
                    sql"""
                    INSERT INTO interaction (id, host, port, request, response, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    cid, host, port, req, res, timestamp)
                db.close()
            except: return false
    true

