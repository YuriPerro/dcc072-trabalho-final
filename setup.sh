#!/bin/bash

# Script para criar certificados para o servidor e cliente DTLS

echo "Criando diretório para certificados..."
mkdir -p certs

# Verifica se os certificados já existem
if [ -f "certs/server_cert.pem" ] && [ -f "certs/server_key.pem" ] && \
   [ -f "certs/client_cert.pem" ] && [ -f "certs/client_key.pem" ]; then
    echo "Certificados já existem, pulando a criação."
else
    echo "Gerando certificados para o servidor..."
    openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
        -keyout certs/server_key.pem -out certs/server_cert.pem \
        -subj "/C=BR/ST=Estado/L=Cidade/O=Organizacao/OU=TI/CN=servidor.dtls.local" \
        -addext "subjectAltName = DNS:servidor.dtls.local,IP:127.0.0.1"

    echo "Gerando certificados para o cliente..."
    openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
        -keyout certs/client_key.pem -out certs/client_cert.pem \
        -subj "/C=BR/ST=Estado/L=Cidade/O=Organizacao/OU=TI/CN=cliente.dtls.local" \
        -addext "subjectAltName = DNS:cliente.dtls.local,IP:127.0.0.1"
fi

echo "Configuração concluída!" 