#!/usr/bin/env python

import argparse
import logging
import socket
import threading
import time

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DtlsMitmAttack:
    """
    Implementa um ataque Man-in-the-Middle simples para comunicação DTLS.
    Intercepta pacotes entre cliente e servidor, permitindo visualizar ou modificar o tráfego.
    """
    
    def __init__(self, server_host='127.0.0.1', server_port=5555, mitm_port=5556):
        """
        Inicializa o ataque MITM.
        
        Args:
            server_host: Endereço IP do servidor DTLS real
            server_port: Porta do servidor DTLS real
            mitm_port: Porta em que o MITM vai escutar
        """
        self.server_host = server_host
        self.server_port = server_port
        self.mitm_port = mitm_port
        
        # Endereço do servidor real
        self.server_addr = (server_host, server_port)
        
        # Socket para comunicação com o cliente
        self.client_socket = None
        
        # Socket para comunicação com o servidor
        self.server_socket = None
        
        # Flag para controlar a execução
        self.running = False
        
        # Contador de pacotes
        self.packet_count = 0
        
        # Modo de ataque
        self.attack_mode = "passive"  # passive, modify, drop
        
        # Probabilidade de modificar/descartar pacotes (0.0 - 1.0)
        self.attack_probability = 0.5
        
        # Threads
        self.client_to_server_thread = None
        self.server_to_client_thread = None
        
        # Dicionário para armazenar endereços de clientes
        self.client_addresses = {}
    
    def start(self):
        """Inicia o ataque MITM"""
        try:
            # Cria socket para receber conexões dos clientes
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.client_socket.bind(('0.0.0.0', self.mitm_port))
            
            # Cria socket para comunicação com o servidor
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.settimeout(2.0)  # Timeout para não bloquear indefinidamente
            
            logger.info(f"Ataque MITM iniciado - escutando na porta {self.mitm_port}")
            logger.info(f"Redirecionando tráfego para {self.server_host}:{self.server_port}")
            logger.info(f"Modo de ataque: {self.attack_mode}")
            
            if self.attack_mode in ["modify", "drop"]:
                logger.info(f"Probabilidade de ataque: {self.attack_probability * 100}%")
            
            self.running = True
            
            # Inicia threads para encaminhar tráfego
            self.client_to_server_thread = threading.Thread(target=self._handle_client_to_server)
            self.server_to_client_thread = threading.Thread(target=self._handle_server_to_client)
            
            self.client_to_server_thread.daemon = True
            self.server_to_client_thread.daemon = True
            
            self.client_to_server_thread.start()
            self.server_to_client_thread.start()
            
            # Aguarda interrupção do usuário
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Ataque MITM interrompido pelo usuário")
                self.stop()
        
        except Exception as e:
            logger.error(f"Erro ao iniciar ataque MITM: {e}")
            self.stop()
    
    def stop(self):
        """Para o ataque MITM"""
        self.running = False
        
        if self.client_socket:
            self.client_socket.close()
        
        if self.server_socket:
            self.server_socket.close()
        
        logger.info(f"Ataque MITM encerrado. Total de pacotes interceptados: {self.packet_count}")
    
    def _handle_client_to_server(self):
        """Gerencia o tráfego do cliente para o servidor"""
        while self.running:
            try:
                # Recebe dados do cliente
                data, addr = self.client_socket.recvfrom(4096)
                
                # Armazena o endereço do cliente para resposta
                self.client_addresses[addr[0]] = addr
                
                self.packet_count += 1
                logger.info(f"[{self.packet_count}] Cliente ({addr}) -> Servidor: {len(data)} bytes")
                
                # Aplica o ataque conforme o modo selecionado
                if self._should_attack():
                    if self.attack_mode == "modify":
                        # Modifica o pacote (inverte alguns bits)
                        modified_data = self._modify_packet(data)
                        logger.warning(f"[{self.packet_count}] Pacote modificado!")
                        data = modified_data
                    elif self.attack_mode == "drop":
                        # Descarta o pacote
                        logger.warning(f"[{self.packet_count}] Pacote descartado!")
                        continue
                
                # Encaminha para o servidor
                self.server_socket.sendto(data, self.server_addr)
            
            except Exception as e:
                if self.running:
                    logger.error(f"Erro ao encaminhar cliente->servidor: {e}")
    
    def _handle_server_to_client(self):
        """Gerencia o tráfego do servidor para o cliente"""
        while self.running:
            try:
                # Recebe dados do servidor
                data, _ = self.server_socket.recvfrom(4096)
                
                self.packet_count += 1
                logger.info(f"[{self.packet_count}] Servidor -> Cliente: {len(data)} bytes")
                
                # Aplica o ataque conforme o modo selecionado
                if self._should_attack():
                    if self.attack_mode == "modify":
                        # Modifica o pacote
                        modified_data = self._modify_packet(data)
                        logger.warning(f"[{self.packet_count}] Pacote modificado!")
                        data = modified_data
                    elif self.attack_mode == "drop":
                        # Descarta o pacote
                        logger.warning(f"[{self.packet_count}] Pacote descartado!")
                        continue
                
                # Encaminha para todos os clientes conhecidos
                # Em DTLS, precisamos garantir que as respostas cheguem ao cliente correto
                for client_ip, client_addr in list(self.client_addresses.items()):
                    try:
                        self.client_socket.sendto(data, client_addr)
                    except Exception as e:
                        logger.error(f"Erro ao enviar para cliente {client_addr}: {e}")
                        # Remove cliente problemático
                        if client_ip in self.client_addresses:
                            del self.client_addresses[client_ip]
            
            except socket.timeout:
                # Timeout normal, continua o loop
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Erro ao encaminhar servidor->cliente: {e}")
    
    def _should_attack(self):
        """Determina se deve aplicar o ataque com base na probabilidade configurada"""
        if self.attack_mode == "passive":
            return False
        
        import random
        return random.random() < self.attack_probability
    
    def _modify_packet(self, data):
        """
        Modifica o pacote para simular um ataque.
        Altera alguns bytes do payload, preservando o cabeçalho.
        """
        # Preserva os primeiros bytes (cabeçalho) e modifica alguns bytes do payload
        header_size = min(8, len(data))
        header = data[:header_size]
        payload = bytearray(data[header_size:])
        
        # Modifica alguns bytes do payload (se houver payload)
        if payload:
            # Modifica até 3 bytes ou o tamanho do payload, o que for menor
            num_bytes_to_modify = min(3, len(payload))
            for _ in range(num_bytes_to_modify):
                if payload:  # Verifica novamente para garantir
                    import random
                    idx = random.randint(0, len(payload) - 1)
                    payload[idx] = (payload[idx] + 1) % 256  # Incrementa o byte
        
        # Retorna o pacote modificado
        return header + bytes(payload)

def parse_arguments():
    """Processa os argumentos da linha de comando"""
    parser = argparse.ArgumentParser(description="Ataque MITM para DTLS")
    
    parser.add_argument("--server-host", default="127.0.0.1", help="Endereço IP do servidor DTLS")
    parser.add_argument("--server-port", type=int, default=5555, help="Porta do servidor DTLS")
    parser.add_argument("--mitm-port", type=int, default=5556, help="Porta em que o MITM vai escutar")
    parser.add_argument("--mode", choices=["passive", "modify", "drop"], default="passive",
                        help="Modo de ataque: passive (apenas observa), modify (modifica pacotes) ou drop (descarta pacotes)")
    parser.add_argument("--probability", type=float, default=0.5,
                        help="Probabilidade de modificar/descartar pacotes (0.0 - 1.0)")
    
    return parser.parse_args()

def print_instructions(mitm_port):
    """Exibe instruções para o usuário"""
    print("\n" + "="*80)
    print("INSTRUÇÕES PARA TESTAR O ATAQUE MITM".center(80))
    print("="*80)
    print(f"1. Mantenha este script em execução (escutando na porta {mitm_port})")
    print(f"2. Inicie o servidor normalmente: python server.py")
    print(f"3. Execute o cliente apontando para o MITM:")
    print(f"   python client.py --port {mitm_port}")
    print("\nO tráfego será interceptado e redirecionado automaticamente.")
    print("="*80 + "\n")

if __name__ == "__main__":
    args = parse_arguments()
    
    # Cria e inicia o ataque MITM
    mitm = DtlsMitmAttack(args.server_host, args.server_port, args.mitm_port)
    mitm.attack_mode = args.mode
    mitm.attack_probability = args.probability
    
    # Exibe instruções
    print_instructions(args.mitm_port)
    
    # Inicia o ataque
    mitm.start() 