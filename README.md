# DTLS Secure Communication Demo

Este projeto implementa uma comunicação segura utilizando o protocolo DTLS (Datagram Transport Layer Security) sobre UDP, com recursos para demonstração de ataques Man-in-the-Middle (MITM) e mecanismos de proteção.

## Requisitos

- Python 3.6+
- OpenSSL
- Wireshark (opcional, para análise de pacotes)

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/YuriPerro/dcc072-trabalho-final.git
cd dcc072-trabalho-final
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

3. Gere os certificados necessários:
```bash
./setup.sh
```

## Estrutura do Projeto

- `server.py` - Servidor DTLS que recebe mensagens seguras
- `client.py` - Cliente DTLS que envia mensagens ao servidor
- `mitm_attack.py` - Ferramenta para demonstrar ataques Man-in-the-Middle
- `certs/` - Diretório para armazenamento de certificados
- `requirements.txt` - Dependências do projeto

## Como Usar

### Executando o Servidor

```bash
python server.py
```

Por padrão, o servidor escuta na porta 5555.

### Executando o Cliente

```bash
python client.py --count 5
```

Opções:
- `--count <número>`: Número de mensagens a enviar (padrão: 5)
- `--host <endereço>`: Endereço do servidor (padrão: 127.0.0.1)
- `--port <porta>`: Porta do servidor (padrão: 5555)

### Demonstrando Ataques Man-in-the-Middle (MITM)

O ataque MITM intercepta a comunicação entre cliente e servidor, permitindo visualizar, modificar ou descartar pacotes.

#### Executando o Ataque MITM

```bash
python mitm_attack.py
```

Por padrão, o MITM escuta na porta 5556 e encaminha o tráfego para o servidor na porta 5555.

Opções:
- `--server-host <endereço>`: Endereço do servidor real (padrão: 127.0.0.1)
- `--server-port <porta>`: Porta do servidor real (padrão: 5555)
- `--mitm-port <porta>`: Porta em que o MITM vai escutar (padrão: 5556)
- `--mode <modo>`: Modo de ataque (padrão: passive)
  - `passive`: Apenas observa o tráfego
  - `modify`: Modifica pacotes aleatoriamente
  - `drop`: Descarta pacotes aleatoriamente
- `--probability <valor>`: Probabilidade de modificar/descartar pacotes (0.0 - 1.0, padrão: 0.5)

#### Testando o Ataque

1. Inicie o servidor DTLS:
```bash
python server.py
```

2. Inicie o ataque MITM:
```bash
python mitm_attack.py --mode modify
```

3. Execute o cliente apontando para o MITM:
```bash
python client.py --port 5556
```

O MITM interceptará a comunicação entre cliente e servidor, permitindo observar, modificar ou descartar pacotes conforme o modo selecionado.

## Tecnologias Utilizadas

- **Python**: Linguagem de programação principal
- **PyOpenSSL**: Implementação Python da biblioteca OpenSSL
- **Socket**: Comunicação de rede
- **Threading**: Processamento paralelo para o ataque MITM
- **DTLS**: Protocolo de segurança para datagramas
- **Logging**: Registros de eventos e mensagens do sistema