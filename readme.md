# Simple HTTPS Mitm proxy in Nim

I'm currently trying to learn how proxies work.

This project will try to implement a HTTP MITM proxy, meaning HTTP and HTTPS requests will be able to be inspected and modified to resend them.

There will also be an attempt at supporting Websockets proxying and an implementation of SOCKS(unsure about this one since it's time consuming)

Feel free to copy and modify for your uses, the quality of the code is not garanteed, since this is a learning project.

---

The MITM proxy is now functionnal for the most part.
I will start working on some higher level functionality, like saving requests, replaying them (repeater) and sequencing payloads (intruder).

Steps to use:

```bash
# 1 - Start the proxy once
nim r -d:ssl proxy.nim

# 2 - This will generate a ca.pem file in ./certs, Import this file as an authority in your browser/system
# 3 - Relaunch the proxy
# 4 - configure it in your browser/tool
#Certificates should generate on the fly to negotiate SSL with the right SAN for a given host. 

# For release:
nim c -d:ssl -d:release proxy.nim
./proxy.nim --host 127.0.0.1 --port 8081
# This will launch the proxy, the requests/responses will be written to disk in './interactions' directory.


# If you want to use the webapp
cd webapp
pip install -r requirements.txt
./app.py

```

For now, it is pretty scuffed, but it's a WIP.
