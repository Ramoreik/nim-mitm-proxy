#!/usr/bin/env bash

certs_dir="certs"
mkdir -p "${certs_dir}"


echo "[*] Creating root key :: ${certs_dir}/ca.key.pem"
openssl genrsa -out "${certs_dir}/ca.key.pem" 2048
chmod 400 "${certs_dir}/ca.key.pem"


echo "[*] Creating root CA :: ${certs_dir}/ca.pem"
openssl req -new -x509 \
  -subj "/CN=NemesisMITM" \
  -extensions v3_ca \
  -days 3650 \
  -key "${certs_dir}/ca.key.pem" \
  -sha256 -out "${certs_dir}/ca.pem" \
  -config "scripts/template.cnf"



