import socket
import struct
import threading
import queue
import time
from typing import List, Dict, Tuple

class ScannerRede:
    def __init__(self):
        self.hosts_ativos = []
        self.portas_abertas = {}
        self.fila = queue.Queue()
        self.lock = threading.Lock()
    
    def obter_ip_rede(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def calcular_mascara_rede(self, ip: str) -> str:
        partes = ip.split('.')
        if len(partes) == 4:
            return f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"
        return "192.168.1.0/24"
    
    def verificar_host(self, ip: str) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            resultado = s.connect_ex((ip, 80))
            s.close()
            return resultado == 0
        except:
            return False
    
    def escanear_porta(self, ip: str, porta: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            resultado = s.connect_ex((ip, porta))
            s.close()
            return resultado == 0
        except:
            return False
    
    def trabalhador_portas(self):
        while True:
            try:
                ip, porta = self.fila.get_nowait()
                if self.escanear_porta(ip, porta):
                    with self.lock:
                        if ip not in self.portas_abertas:
                            self.portas_abertas[ip] = []
                        self.portas_abertas[ip].append(porta)
                self.fila.task_done()
            except queue.Empty:
                break
            except:
                continue
    
    def escanear_rede(self, rede: str = None) -> List[str]:
        if not rede:
            ip = self.obter_ip_rede()
            rede = self.calcular_mascara_rede(ip)
        
        ip_base = rede.split('/')[0]
        partes = ip_base.split('.')
        ip_base = f"{partes[0]}.{partes[1]}.{partes[2]}."
        
        threads = []
        for i in range(1, 255):
            ip = f"{ip_base}{i}"
            t = threading.Thread(target=self.verificar_host, args=(ip,))
            threads.append(t)
            t.start()
            
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        return self.hosts_ativos
    
    def escanear_portas(self, ip: str, portas: List[int] = None) -> List[int]:
        if not portas:
            portas = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]
        
        threads = []
        for porta in portas:
            self.fila.put((ip, porta))
        
        for _ in range(min(50, len(portas))):
            t = threading.Thread(target=self.trabalhador_portas)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        return self.portas_abertas.get(ip, [])
    
    def obter_servico(self, porta: int) -> str:
        servicos = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Proxy"
        }
        return servicos.get(porta, "Desconhecido") 