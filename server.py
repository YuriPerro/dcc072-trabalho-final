#!/usr/bin/env python

import socket
import logging
import os
import sys
import OpenSSL.SSL

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Para fins de demonstração do ataque de replay, esta flag pode ser definida como False
# Em um ambiente de produção real, deve ser sempre True
ANTI_REPLAY_PROTECTION = False

def create_dtls_server(host='127.0.0.1', port=5555):
    """Cria e executa um servidor DTLS"""
    try:
        # Verifica se os certificados existem
        cert_path = 'certs/server_cert.pem'
        key_path = 'certs/server_key.pem'
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.error(f"Certificados não encontrados. Execute './setup.sh' para gerar.")
            return

        # Cria um socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_addr = (host, port)
        sock.bind(server_addr)
        
        # Configura timeout para não bloquear indefinidamente
        sock.settimeout(5.0)
        
        # Cria um contexto DTLS
        context = OpenSSL.SSL.Context(OpenSSL.SSL.DTLS_SERVER_METHOD)
        context.use_certificate_file(cert_path)
        context.use_privatekey_file(key_path)
        context.check_privatekey()
        context.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *args: True)
        
        # Informa sobre o estado da proteção anti-replay
        if ANTI_REPLAY_PROTECTION:
            logger.info("Proteção anti-replay: ATIVADA")
        else:
            logger.warning("Proteção anti-replay: DESATIVADA (vulnerável a ataques)")
            
        logger.info(f"Servidor DTLS rodando em {server_addr}")
        
        # Dicionário para armazenar conexões de clientes
        clients = {}
        
        # Lista de clientes encerrados recentemente
        # Isso evita que pacotes retardatários de clientes desconectados
        # sejam interpretados como novas conexões
        recently_closed = set()
        
        # Rastreamento de mensagens para detecção de replay (apenas com proteção ativada)
        message_tracker = {}
        
        while True:
            try:
                # Recebe dados
                data, client_addr = sock.recvfrom(4096)
                
                # Ignora pacotes de clientes que acabaram de encerrar a conexão
                if ANTI_REPLAY_PROTECTION and client_addr in recently_closed:
                    logger.debug(f"Ignorando pacote retardatário de {client_addr}")
                    continue
                
                # Verifica se é uma nova conexão ou existente
                if client_addr not in clients:
                    logger.info(f"Nova conexão de {client_addr}")
                    
                    # Cria uma nova conexão DTLS
                    conn = OpenSSL.SSL.Connection(context, None)
                    conn.set_accept_state()
                    
                    # Mantém socket e estado inicial
                    clients[client_addr] = {
                        'connection': conn,
                        'handshake_complete': False,
                        'message_hashes': set()  # Para rastrear mensagens recebidas
                    }
                
                # Obtém a conexão do cliente
                client = clients[client_addr]
                conn = client['connection']
                
                # Passa os dados para a conexão DTLS
                conn.bio_write(data)
                
                # Se o handshake ainda não foi concluído
                if not client['handshake_complete']:
                    try:
                        # Tenta completar o handshake
                        conn.do_handshake()
                        client['handshake_complete'] = True
                        logger.info(f"Handshake concluído com {client_addr}")
                    except OpenSSL.SSL.WantReadError:
                        # Envia dados de handshake
                        pass
                    except Exception as e:
                        logger.error(f"Erro no handshake: {e}")
                
                # Tenta ler dados se o handshake estiver concluído
                if client['handshake_complete']:
                    try:
                        # Tenta ler dados da conexão
                        request = conn.recv(4096)
                        request_str = request.decode()
                        
                        # Verifica se é mensagem de encerramento
                        if request_str.strip() == "FIM":
                            logger.info(f"Cliente {client_addr} encerrou a conexão")
                            
                            # Adiciona o cliente à lista de recentemente fechados
                            if ANTI_REPLAY_PROTECTION:
                                recently_closed.add(client_addr)
                            
                            # Remove o cliente após o processamento completo
                            del clients[client_addr]
                            
                            # Não envia resposta quando for mensagem de encerramento
                            continue
                        
                        # Verificação de replay attack
                        message_hash = hash(request_str)
                        
                        if ANTI_REPLAY_PROTECTION and message_hash in client['message_hashes']:
                            logger.warning(f"Ataque de replay detectado de {client_addr}! Mensagem: {request_str}")
                            # Não processa a mensagem repetida
                            continue
                        else:
                            # Adiciona o hash da mensagem ao conjunto de mensagens processadas
                            if ANTI_REPLAY_PROTECTION:
                                client['message_hashes'].add(message_hash)
                            
                            logger.info(f"Recebido de {client_addr}: {request_str}")
                        
                        # Envia resposta (eco)
                        conn.send(request)
                        logger.info(f"Resposta preparada para {client_addr}")
                    except OpenSSL.SSL.WantReadError:
                        # Normal durante DTLS
                        pass
                    except Exception as e:
                        logger.error(f"Erro ao processar mensagem: {e}")
                
                # Extrai e envia dados de resposta DTLS
                # Só tenta enviar dados se o cliente ainda estiver conectado
                if client_addr in clients:
                    try:
                        outgoing = conn.bio_read(4096)
                        if outgoing:
                            sock.sendto(outgoing, client_addr)
                            if client['handshake_complete']:
                                logger.info(f"Resposta enviada para {client_addr}")
                            else:
                                logger.debug(f"Enviando dados de handshake para {client_addr}")
                    except Exception as e:
                        logger.error(f"Erro ao enviar dados: {e}")
                     
                # Limpa a lista de clientes fechados se ficar muito grande
                if len(recently_closed) > 100:
                    recently_closed.clear()
                    
            except socket.timeout:
                # Timeout normal
                pass
            except KeyboardInterrupt:
                logger.info("Servidor encerrado pelo usuário")
                break
            except Exception as e:
                logger.error(f"Erro: {e}")
        
    except Exception as e:
        logger.error(f"Erro fatal: {e}")
    finally:
        if 'sock' in locals():
            sock.close()
            logger.info("Servidor encerrado")

if __name__ == "__main__":
    create_dtls_server()