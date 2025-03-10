# Implementação de Comunicação Segura com DTLS

Este projeto implementa um sistema de comunicação cliente-servidor utilizando o protocolo Datagram Transport Layer Security (DTLS) sobre o User Datagram Protocol (UDP). A implementação garante a segurança da comunicação através do DTLS, proporcionando confidencialidade, integridade e autenticação.

## Estrutura do Projeto

- `server.py`: Servidor DTLS que recebe e responde mensagens de forma segura
- `client.py`: Cliente DTLS que envia mensagens seguras para o servidor
- `certs/`: Diretório contendo certificados e chaves para autenticação
- `setup.sh`: Script para gerar os certificados necessários

## Requisitos

- Python 3.6+
- PyOpenSSL
- cryptography

Para instalar as dependências:

```bash
pip install -r requirements.txt
```

## Executando o Projeto

### 1. Gerar Certificados

Execute o script de configuração para gerar os certificados necessários:

```bash
./setup.sh
```

### 2. Iniciar o Servidor

```bash
python server.py
```

O servidor será iniciado na porta 5555 e aguardará conexões de clientes.

### 3. Iniciar o Cliente

Em outro terminal:

```bash
python client.py [--host IP] [--port PORTA] [--count QUANTIDADE] [--delay SEGUNDOS]
```

Parâmetros opcionais:
- `--host`: Endereço IP do servidor (padrão: 127.0.0.1)
- `--port`: Porta do servidor (padrão: 5555)
- `--count`: Número de mensagens a enviar (padrão: 10)
- `--delay`: Tempo de espera entre mensagens em segundos (padrão: 1.0)

## Detalhes da Implementação

O projeto implementa o protocolo DTLS que fornece as seguintes garantias de segurança:

1. **Confidencialidade**: As mensagens são criptografadas usando o protocolo DTLS, impedindo que terceiros possam ler seu conteúdo.
2. **Integridade**: A integridade das mensagens é garantida, assegurando que o conteúdo não foi alterado durante a transmissão.
3. **Autenticação**: O servidor se autentica usando certificados X.509, garantindo sua identidade.
4. **Handshake seguro**: Um processo seguro de handshake é realizado para estabelecer os parâmetros da conexão.

## Fluxo de Comunicação

1. O cliente inicia uma conexão DTLS com o servidor
2. O servidor e o cliente realizam o handshake DTLS
3. As mensagens são trocadas de forma segura
4. O cliente envia "FIM" para encerrar a conexão

## Referências

- [RFC 6347 - Datagram Transport Layer Security Version 1.2](https://tools.ietf.org/html/rfc6347)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [PyOpenSSL Documentation](https://www.pyopenssl.org/en/stable/)