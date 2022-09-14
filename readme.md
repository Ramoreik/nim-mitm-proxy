# Simple HTTP/HTTPS MITM proxy in Nim

## PROJECT STATUS

The MITM proxy is now functionnal.
It can successfully inspect HTTP/HTTPS traffic.

For now, there is a basic flask application that allows to view inspected traffic.
The goal would be to make this application able to at the least repeat requests.

This whole thing is a WIP.

--- 

## Dependencies
The proxy uses openssl under the hood.
Therefore, openssl is necessary.

If something else is missing, the Nim compiler will inform you.

### USAGE:

```bash
# 1 - Start the proxy once
nim r -d:ssl proxy.nim 

# 2 - This will generate a ca.pem file in ./certs, Import this file as an authority in your browser/system
# 3 - Relaunch the proxy
# 4 - configure it in your browser/tool
# Certificates should generate on the fly to negotiate SSL with the right SAN for a given host. 

# For release:
nim c -d:ssl -d:release proxy.nim
./proxy.nim --host 127.0.0.1 --port 8081
# This will launch the proxy, the requests/responses will be written to disk in './interactions' directory.


# If you want to use the webapp
cd webapp
pip install -r requirements.txt
./app.py

```

- the proxy uses cligen, you can use '-h' to list all the options.


