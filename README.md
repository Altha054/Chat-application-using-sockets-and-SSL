Generate a Private Key:

openssl genrsa -out server.key 2048

Generate a Certificate Signing Request (CSR):


openssl req -new -key server.key -out server.csr

Generate a Self-Signed Certificate:


openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

This will generate server.crt and server.key files in the current directory.

If you want to generate a self-signed certificate without a passphrase, you can add -nodes flag to the openssl req command:

openssl req -new -key server.key -out server.csr -nodes



