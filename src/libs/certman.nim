import std/[strformat, strutils, os, re, net]
import utils

let CERTS_D = "certs"
let CONFIG_D = "config"
let CA_KEY = CERTS_D & "/ca.key.pem"
let CA_FILE = CERTS_D & "/ca.pem"
let TEMPLATE_FILE = CONFIG_D & "/template.cnf"
let VALID_HOST = re"^[^']{2,63}"

# CERTMAN :: in charge of generation of certificates and handling of MITM SSL contexts. 

proc getKeyFilename(host: string): string =
    joinPath(CERTS_D, host, host & ".key.pem")

proc getCertFilename(host: string): string =
    joinPath(CERTS_D, host, host & ".crt")

proc getMITMContext*(host: string): SslContext =
    return newContext(
        keyFile = getKeyFilename(host),
        certFile = getCertFilename(host)
    )

proc createCA*(): bool =
    let openssl = findExe("openssl")
    let chmod = findExe("chmod")

    if not dirExists(CERTS_D): createDir(CERTS_D)

    echo fmt"[*] Creating root key :: " & CA_KEY
    if not execCmdWrap(
           openssl & fmt" genrsa -out '{CA_KEY}' 2048"):
        return false

    if not execCmdWrap(
            chmod & fmt" 400 '{CA_KEY}'"):
        return false

    echo fmt"[*] Creating root CA :: {CA_FILE}"
    if not execCmdWrap(
            fmt"""
                {openssl} req -new -x509 \
                -subj '/CN=NemesisMITM' \
                -extensions v3_ca \
                -days 3650 \
                -key '{CA_KEY}' \
                -sha256 \
                -out '{CA_FILE}' \
                -config '{TEMPLATE_FILE}'"""): 
        return false
    true

proc generateHostCertificate(host: string): bool =
    let openssl = findExe("openssl")
    let server_d = CERTS_D & "/" & host
    let key_file = fmt"{server_d}/{host}.key.pem"
    let cert_file = fmt"{server_d}/{host}.crt"
    let csr_file = fmt"{server_d}/{host}.csr"
    let cnf_file = fmt"{server_d}/{host}.cnf"
    let srl_file = fmt"{server_d}/{host}.srl"

    if not match(host, VALID_HOST): 
        echo "[!] Invalid host provided."
        return false

    if not dirExists(server_d): createDir(server_d)

    echo "[*] Creating key for: " & host
    if not execCmdWrap(
            openssl & fmt" genrsa -out '{key_file}'"): 
        return false

    if fileExists(TEMPLATE_FILE):
        var tmpl = open(TEMPLATE_FILE)
        var host_cnf = open(cnf_file, fmWrite)
        try:
            let config = tmpl.readAll().replace("{{domain}}", host) 
            host_cnf.write(config)
        except:
            echo "[!] Error while templating the config file."
            return false
        finally:
            tmpl.close()
            host_cnf.close()

    echo "[*] Creating csr for: " & host
    if not execCmdWrap(
            fmt"""
            {openssl} req -subj '/CN={host}' \
            -extensions v3_req \
            -sha256 -new \
            -key {key_file} \
            -out {csr_file} \
            -config {cnf_file}
            """):
        return false

    echo "[*] Creating cert for: " & host 
    if not execCmdWrap(
            fmt"""
            openssl x509 -req -extensions v3_req \
              -days 3650 -sha256 \
              -in '{csr_file}' \
              -CA '{CA_FILE}' \
              -CAkey '{CA_KEY}' \
              -CAcreateserial \
              -CAserial '{srl_file}' \
              -out "{cert_file}" \
              -extfile "{cnf_file}"            
            """):
        return false
    true

proc handleHostCertificate*(host: string): bool =
        let keyfile = getKeyFilename(host)
        let certfile = getCertFilename(host)         
        if not fileExists(keyfile) or not fileExists(certfile):
            if not generateHostCertificate(host):
                return false
        true




