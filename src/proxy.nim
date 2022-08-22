import std/[logging, strformat, os, asyncdispatch]
import libs/[mitm, certman ]
import cligen

# inspiration taken from: https://xmonader.github.io/nimdays/day15_tcprouter.html
# by inspiration I mean it saved me hours of trial and error since i'm dumb.

# This project is to learn the concepts involved in HTTP/HTTPS proxying, Websockets proxying and SOCKS. 

# to MITM, i have to place myself as the remote client, when im tunnelling.
# meaning:
# 1 - I wrap the socket intented for the remote server with my ssl context
# 2 - I start another socket and i negotiate ssl to the actual target
# 3 - I tunnel the two and I can read the data in the tunnel.
# NOTE: For this to work I also have to generate certs on the fly, implemented poorly for now.

# TODO: Fix Edgecases:
    # FIXME: fix edgecase in www.jumpstart.com, site doesn't load for some reason.
    # FIXME: Investigate weird crash on youtube when browsing videos, only on macos apparently.
# TODO: See if data is encoded before writing the interaction, if it is, unencode it. EX gzip.

proc setupLogging*() = 
    var stdout = newConsoleLogger(
        fmtStr = "[$time][$levelname][NemesisMITM]:",
        levelThreshold = lvlInfo)
    var fileLog = newFileLogger("errors.log", levelThreshold=lvlError)
    addHandler(stdout)
    addHandler(fileLog)

proc run(host: string ="127.0.01", port: int =8081) =
    setupLogging()
    log(lvlInfo, fmt"STARTING on {host}:{$port}.")
    if not dirExists("certs"):
        log(lvlInfo,"Root CA not found, generating :: certs/ca.pem")
        log(lvlInfo,"Do not forget to import/use this CA !")
        if not createCA():
            log(lvlError,"[!] Error while creating CA.")
            quit(QuitFailure)
    try:
        waitFor startMITMProxy(host, port)
    except:
        log(lvlError, "[start] " & getCurrentExceptionMsg())

when isMainModule:
 dispatch run, help={
     "host": "Specify the interface to listen on.",
     "port": "Specify the port to listen on."}
 