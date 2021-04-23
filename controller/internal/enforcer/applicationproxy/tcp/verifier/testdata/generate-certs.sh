#!/bin/bash

# This files generates new certs if the generated certs expire. We cant use openssl as this has aporeto extensions

echo "Generate CA"
tg cert --name myca --org acme --common-name root --is-ca --pass secret --force

echo "Generate Client-IP Cert With Aporeto extensions but missing key tags"
tg cert --name myclient-bad --org acme --common-name client-bad \
        --auth-client --signing-cert myca-cert.pem \
        --signing-cert-key myca-key.pem \
        --signing-cert-key-pass secret \
        --tags "\$controller=10.10.10.10" \
        --ip 10.10.10.10 --force

echo "Generate Client-IP Cert"
tg cert --name myclient-ip --org acme --common-name client-ip \
        --auth-client --signing-cert myca-cert.pem \
        --signing-cert-key myca-key.pem \
        --signing-cert-key-pass secret \
        --tags "\$identity=processingunit" --tags "\$id=some" --tags "\$controller=10.10.10.10" \
        --ip 10.10.10.10 --force

echo "Generate Client-DNS Cert"
tg cert --name myclient-dns --org acme --common-name client-dns \
        --auth-client --signing-cert myca-cert.pem \
        --signing-cert-key myca-key.pem \
        --signing-cert-key-pass secret \
        --tags "\$identity=processingunit" --tags "\$id=some" --tags "\$controller=www.client.com" \
        --dns www.client.com --force

echo "Generate Server Cert"
tg cert --name myserver --org acme --common-name server \
        --auth-server --signing-cert myca-cert.pem \
        --signing-cert-key myca-key.pem \
        --signing-cert-key-pass secret \
        --tags "\$identity=processingunit" --tags "\$id=some" --tags "\$controller=www.server.com" \
        --dns www.server.com --force

rm -f *-key.pem
