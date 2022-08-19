#!/usr/bin/env bash

domain=$1
CERTS_D="./certs"
SERVER_D="${CERTS_D}/${domain}"

if [ ! -d "${SERVER_D}" ];then
  echo "[*] Creating dir for: ${domain}"
  mkdir -p "${SERVER_D}"
fi

echo "[*] Creating key for: ${domain}"
openssl genrsa -out "${SERVER_D}/${domain}.key.pem" 2048

echo "[*] Creating cnf for ${domain}"
sed "s/{{domain}}/${domain}/" scripts/template.cnf > "${SERVER_D}/${domain}.cnf"

echo "[*] Creating csr for: ${domain}"
openssl req -subj "/CN=${domain}" \
  -extensions v3_req \
  -sha256 -new \
  -key "${SERVER_D}/${domain}.key.pem" \
  -out "${SERVER_D}/${domain}.csr"\
  -config "${SERVER_D}/${domain}.cnf"

echo "[*] Creating cert for: ${domain} >> ${SERVER_D}.crt"
openssl x509 -req -extensions v3_req \
  -days 3650 -sha256 \
  -in "${SERVER_D}/${domain}.csr" \
  -CA "${CERTS_D}/ca.pem" \
  -CAkey "${CERTS_D}/ca.key.pem" \
  -CAcreateserial \
  -CAserial "${SERVER_D}/${domain}.srl" \
  -out "${SERVER_D}/${domain}.crt" \
  -extfile "${SERVER_D}/${domain}.cnf"

echo "[*] Files created !"
