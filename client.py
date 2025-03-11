#!/usr/bin/env python

import socket
import logging
import time
import argparse
import os
import OpenSSL.SSL

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_dtls_client(server_host='127.0.0.1', server_port=5555, message_count=10, delay=1.0):
    """Cria e executa um cliente DTLS"""
    server_addr = (server_host, server_port)
    
    try:
        # Cria um socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10.0)  # Timeout mais longo para o handshake através do MITM
        logger.info(f"Iniciando conexão DTLS com o servidor {server_addr}")
        
        # Cria um contexto DTLS
        context = OpenSSL.SSL.Context(OpenSSL.SSL.DTLS_CLIENT_METHOD)
        context.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *args: True)
        
        # Cria uma conexão DTLS
        conn = OpenSSL.SSL.Connection(context, None)
        conn.set_connect_state()
        
        # Inicia o handshake
        try:
            conn.do_handshake()
        except OpenSSL.SSL.WantReadError:
            pass  # Comportamento esperado
        
        # Extrai e envia dados de handshake inicial
        outgoing = conn.bio_read(4096)
        if outgoing:
            sock.sendto(outgoing, server_addr)
            logger.debug("Dados de handshake inicial enviados")
        
        # Realiza o handshake
        handshake_complete = False
        handshake_attempts = 0
        max_attempts = 15  # Aumenta o número de tentativas para o MITM
        
        while not handshake_complete and handshake_attempts < max_attempts:
            try:
                handshake_attempts += 1
                logger.debug(f"Tentativa de handshake {handshake_attempts}/{max_attempts}")
                
                # Recebe resposta do servidor
                data, addr = sock.recvfrom(4096)
                if addr != server_addr:
                    logger.warning(f"Recebido pacote de origem inesperada: {addr}")
                    continue
                
                # Passa os dados para a conexão DTLS
                conn.bio_write(data)
                
                # Tenta concluir o handshake
                try:
                    conn.do_handshake()
                    handshake_complete = True
                    logger.info("Handshake DTLS concluído com sucesso")
                except OpenSSL.SSL.WantReadError:
                    # Extrai e envia mais dados de handshake
                    outgoing = conn.bio_read(4096)
                    if outgoing:
                        sock.sendto(outgoing, server_addr)
            except socket.timeout:
                logger.warning(f"Timeout na tentativa {handshake_attempts}")
                # Reenviar dados de handshake
                outgoing = conn.bio_read(4096)
                if outgoing:
                    sock.sendto(outgoing, server_addr)
            except Exception as e:
                logger.error(f"Erro na tentativa {handshake_attempts}: {e}")
        
        if not handshake_complete:
            logger.error(f"Falha no handshake após {max_attempts} tentativas")
            return
        
        # Ajusta timeout para operações normais
        sock.settimeout(5.0)  # Aumenta o timeout para operações através do MITM
        
        # Envia mensagens
        for i in range(message_count):
            message = f"Mensagem de teste #{i+1}"
            
            try:
                # Envia a mensagem
                conn.send(message.encode())
                logger.debug(f"Mensagem formatada: {message}")
                
                # Extrai e envia dados criptografados
                outgoing = conn.bio_read(4096)
                if outgoing:
                    sock.sendto(outgoing, server_addr)
                    logger.info(f"Enviado: {message}")
                
                # Recebe a resposta
                data, addr = sock.recvfrom(4096)
                if addr != server_addr:
                    logger.warning(f"Recebido pacote de origem inesperada: {addr}")
                    continue
                
                # Processa a resposta
                conn.bio_write(data)
                response = conn.recv(4096)
                logger.info(f"Resposta do servidor: {response.decode()}")
            except socket.timeout:
                logger.warning(f"Timeout ao aguardar resposta para mensagem #{i+1}")
            except Exception as e:
                logger.error(f"Erro ao processar mensagem #{i+1}: {e}")
            
            time.sleep(delay)
        
        # Encerra a conexão
        try:
            # Envia mensagem de encerramento
            logger.info("Enviando mensagem de encerramento")
            conn.send(b"FIM")
            outgoing = conn.bio_read(4096)
            if outgoing:
                sock.sendto(outgoing, server_addr)
                logger.info("Mensagem de encerramento enviada")
            
            # Pequena pausa para garantir que a mensagem seja processada
            time.sleep(0.5)
            
            # Não esperamos por resposta a mensagem FIM
        except Exception as e:
            logger.warning(f"Erro ao encerrar conexão: {e}")
    
    except KeyboardInterrupt:
        logger.info("Cliente encerrado pelo usuário")
    except Exception as e:
        logger.error(f"Erro: {e}")
    finally:
        if 'sock' in locals():
            sock.close()
            logger.info("Cliente encerrado")

def parse_arguments():
    """Processa os argumentos da linha de comando"""
    parser = argparse.ArgumentParser(description="Cliente DTLS")
    parser.add_argument("--host", default="127.0.0.1", help="Endereço IP do servidor")
    parser.add_argument("--port", type=int, default=5555, help="Porta do servidor")
    parser.add_argument("--count", type=int, default=10, help="Número de mensagens a enviar")
    parser.add_argument("--delay", type=float, default=1.0, help="Tempo de espera entre mensagens (segundos)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    create_dtls_client(args.host, args.port, args.count, args.delay)