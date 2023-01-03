openssl req -x509 -newkey rsa:1024 -keyout key.pem -out cert.pem -sha256 -days 365 -noenc -subj "/C=DK/ST=Hovedstaden/L=København/O=.../OU=.../CN=.../emailAddress=..."
openssl pkcs12 -export -out example.pfx -inkey key.pem -in cert.pem -passout pass:
openssl pkcs12 -export -out example2.pfx -in cert.pem -inkey key.pem -certpbe NONE -passout pass:1234