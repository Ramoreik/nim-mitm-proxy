import std/[osproc, strformat,
            logging, os, times, db_sqlite]

let INTERACTIONS_D = "interactions"
let CNF_TEMPLATE* = """
HOME    = .
oid_section     = new_oids

[ new_oids ]
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

[ ca ]
default_ca  = CA_default        

[ CA_default ]
dir     = ./demoCA      
certs       = $dir/certs        
crl_dir     = $dir/crl      
database    = $dir/index.txt    
new_certs_dir   = $dir/newcerts     
certificate = $dir/cacert.pem   
serial      = $dir/serial       
crlnumber   = $dir/crlnumber    
crl     = $dir/crl.pem      
private_key = $dir/private/cakey.pem
x509_extensions = usr_cert      
name_opt    = ca_default        
cert_opt    = ca_default        
default_days    = 365           
default_crl_days= 30            
default_md  = default       
preserve    = no            
policy      = policy_match

[ policy_match ]
countryName     = match
stateOrProvinceName = match
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_anything ]
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ req ]
default_bits        = 2048
default_keyfile     = privkey.pem
distinguished_name  = req_distinguished_name
attributes      = req_attributes
x509_extensions = v3_ca 
string_mask = utf8only
req_extensions = v3_req

[ req_distinguished_name ]
countryName         = Country Name (2 letter code)
countryName_default     = AU
countryName_min         = 2
countryName_max         = 2
stateOrProvinceName     = State or Province Name (full name)
stateOrProvinceName_default = Some-State
localityName            = Locality Name (eg, city)
0.organizationName      = Organization Name (eg, company)
0.organizationName_default  = Internet Widgits Pty Ltd
organizationalUnitName      = Organizational Unit Name (eg, section)
commonName          = Common Name (e.g. server FQDN or YOUR name)
commonName_max          = 64
emailAddress            = Email Address
emailAddress_max        = 64

[ req_attributes ]
challengePassword       = A challenge password
challengePassword_min       = 4
challengePassword_max       = 20
unstructuredName        = An optional company name

[ usr_cert ]
basicConstraints=CA:FALSE
nsComment           = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = {{domain}}

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical, CA:TRUE, pathlen:3
keyUsage = critical, cRLSign, keyCertSign
nsCertType = sslCA, emailCA
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical,CA:true

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment           = "OpenSSL Generated Certificate"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

[ tsa ]
default_tsa = tsa_config1   

[ tsa_config1 ]
dir     = ./demoCA      
serial      = $dir/tsaserial    
crypto_device   = builtin       
signer_cert = $dir/tsacert.pem  
certs       = $dir/cacert.pem   
signer_key  = $dir/private/tsakey.pem
signer_digest  = sha256         
default_policy  = tsa_policy1       
other_policies  = tsa_policy2, tsa_policy3  
digests     = sha1, sha256, sha384, sha512
accuracy    = secs:1, millisecs:500, microsecs:100  
clock_precision_digits  = 0 
ordering        = yes   
tsa_name        = yes   
ess_cert_id_chain   = no    
ess_cert_id_alg     = sha1  
"""


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
                    port INTEGER,
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
                var insert = db.prepare("""
                    INSERT INTO interaction (id, host, port, request, response, timestamp) 
                    VALUES (?, ?, ?, ?, ?, ?)""")
                insert.bindParams(cid, host, port, req, res, timestamp)
                if not db.tryExec(insert): 
                    log(lvlError, getCurrentExceptionMsg())
                    return false
                finalize(insert)
                db.close()
            except: 
                log(lvlError, getCurrentExceptionMsg())
                return false
    true

