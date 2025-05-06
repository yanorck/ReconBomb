import socket
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from utils.port_services import obter_nome_servico
import subprocess
import platform

def verificar_ping(host):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', '1', host]
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except:
        return False

def verificar_porta(ip, porta):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            resultado = s.connect_ex((ip, porta))
            return resultado == 0
    except:
        return False

def descobrir_hosts(rede):
    hosts_ativos = []
    partes_rede = rede.split('.')
    ip_base = '.'.join(partes_rede[:3])
    
    def verificar_host(ip):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((ip, 80))
                hosts_ativos.append(ip)
        except:
            pass

    with ThreadPoolExecutor(max_workers=50) as executor:
        tarefas = []
        for i in range(1, 255):
            ip = f"{ip_base}.{i}"
            tarefas.append(executor.submit(verificar_host, ip))
        
        for tarefa in tqdm(tarefas, total=254, desc="Escaneando rede"):
            try:
                tarefa.result(timeout=2)
            except:
                continue
    
    return hosts_ativos

def escanear_tcp(ip, portas, max_threads=50):
    resultados = {}
    
    def escanear_porta(porta):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                resultado = s.connect_ex((str(ip), porta))
                if resultado == 0:
                    resultados[porta] = "Aberta"
                    servico = obter_nome_servico(porta)
                    tqdm.write(f"Porta {porta}: Aberta - {servico}")
                else:
                    resultados[porta] = "Fechada"
        except Exception:
            resultados[porta] = "Filtrada"

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            list(tqdm(executor.map(escanear_porta, portas), total=len(portas), desc="Escaneando TCP"))
    except KeyboardInterrupt:
        print("\nEscaneamento TCP interrompido")
    except Exception as e:
        print(f"\nErro durante escaneamento TCP: {e}")
    
    return resultados

def escanear_udp(ip, portas, max_threads=50):
    resultados = {}

    def escanear_porta(porta):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.3)
                s.sendto(b"", (str(ip), porta))
                try:
                    dados, _ = s.recvfrom(1024)
                    resultados[porta] = "Aberta" if dados else "Fechada"
                except socket.timeout:
                    resultados[porta] = "Aberta"
        except Exception:
            resultados[porta] = "Filtrada"

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            list(tqdm(executor.map(escanear_porta, portas), total=len(portas), desc="Escaneando UDP"))
    except KeyboardInterrupt:
        print("\nEscaneamento UDP interrompido")
    except Exception as e:
        print(f"\nErro durante escaneamento UDP: {e}")
    
    return resultados

def capturar_banner(ip, porta):
    try:
        with socket.socket() as s:
            s.settimeout(3)
            s.connect((str(ip), porta))

            if porta == 80 or porta == 8080:
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + str(ip).encode() + b"\r\n\r\n")

            banner = s.recv(1024).decode().strip()
            return banner
    except socket.timeout:
        print(f"Erro ao capturar banner na porta {porta}: Timeout")
    except Exception as e:
        print(f"Erro ao capturar banner na porta {porta}: {e}")
    return None

def detectar_os(ip):
    portas_teste = [80, 443, 22, 21, 445, 139, 135, 3389]
    assinaturas_os = {
        'windows': ['windows', 'microsoft', 'iis', 'asp.net'],
        'linux': ['linux', 'ubuntu', 'debian', 'centos', 'apache', 'nginx'],
        'unix': ['unix', 'bsd', 'darwin', 'macos']
    }
    
    for porta in portas_teste:
        try:
            with socket.socket() as s:
                s.settimeout(3)
                s.connect((str(ip), porta))
                
                if porta in [80, 443]:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: " + str(ip).encode() + b"\r\n\r\n")
                elif porta == 22:
                    s.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
                elif porta == 445:
                    s.sendall(b"\x00\x00\x00\xa4\xff\x53\x4d\x42\x72\x00\x00\x00\x00")
                
                resposta = s.recv(1024).decode().lower()
                
                for tipo_os, assinaturas in assinaturas_os.items():
                    if any(assinatura in resposta for assinatura in assinaturas):
                        return {
                            "status": "sucesso",
                            "os": tipo_os.capitalize(),
                            "detalhes": f"Detecção baseada em resposta da porta {porta}"
                        }
                
                return {
                    "status": "sucesso",
                    "os": "Desconhecido",
                    "detalhes": f"Conexão bem sucedida na porta {porta}, mas não foi possível identificar o OS"
                }
                
        except socket.timeout:
            continue
        except:
            continue
    
    return {
        "status": "erro",
        "os": "Não foi possível detectar",
        "detalhes": "Nenhuma porta respondeu à tentativa de conexão"
    }

class ScannerPortas:
    def __init__(self):
        self.portas_comuns = list(range(1, 1025))
    
    def escanear_tcp(self, ip):
        return escanear_tcp(ip, self.portas_comuns)
    
    def escanear_udp(self, ip):
        return escanear_udp(ip, self.portas_comuns)
    
    def escanear_tudo(self, ip):
        return {
            'tcp': self.escanear_tcp(ip),
            'udp': self.escanear_udp(ip)
        }
    
    def obter_banners(self, ip):
        banners = {}
        for porta in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]:
            banner = capturar_banner(ip, porta)
            if banner:
                banners[porta] = banner
        return banners
    
    def detectar_os(self, ip):
        return detectar_os(ip) 