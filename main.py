from utils.cli import (
    mostrar_banner, mostrar_menu_principal, mostrar_menu_escaneamento,
    obter_entrada, mostrar_resultados, mostrar_erro, mostrar_sucesso,
    mostrar_progresso, display_hosts
)
from modules.web.tech_detector import DetectorTecnologias
from modules.web.waf_detector import DetectorWAF
from modules.web.ssl_analyzer import AnalisadorSSL
from modules.web.dir_scanner import EscaneadorDiretorios
from modules.dns.enumerator import EnumeradorDNS
from modules.network.network_scanner import ScannerRede
import socket
import sys
import urllib3
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import unquote, urlparse
from tqdm import tqdm
import os
import subprocess

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def executar_portscan():
    """Executa o script main.py do módulo portscan"""
    try:
        # Construa o caminho para o arquivo main.py
        caminho_portscan = os.path.join('modules', 'port_scan', 'main.py')
        
        # Verifique se o arquivo existe
        if not os.path.exists(caminho_portscan):
            mostrar_erro("Arquivo port_scan/main.py não encontrado!")
            return
        
        # Execute o arquivo usando o interpretador Python
        subprocess.run([sys.executable, caminho_portscan])
        
    except Exception as e:
        mostrar_erro(f"Erro ao executar portscan: {str(e)}")
    except Exception as e:
        mostrar_erro(f"Erro inesperado: {str(e)}")


def reconhecimento_web(alvo):
    mostrar_progresso("Iniciando reconhecimento web...")
    detector_tech = DetectorTecnologias()
    resultados_tech = detector_tech.detectar_tecnologias(alvo)
    mostrar_resultados("Tecnologias Detectadas", resultados_tech)
    detector_waf = DetectorWAF()
    resultados_waf = detector_waf.detectar_waf(alvo)
    mostrar_resultados("WAF Detectado", resultados_waf)
    analisador_ssl = AnalisadorSSL()
    resultados_ssl = analisador_ssl.obter_info_certificado(alvo)
    mostrar_resultados("Informações do Certificado SSL/TLS", resultados_ssl)
    protocolos_ssl = analisador_ssl.verificar_protocolos_ssl(alvo)
    mostrar_resultados("Protocolos SSL/TLS Suportados", protocolos_ssl)
    resultados_hsts = analisador_ssl.verificar_hsts(alvo)
    mostrar_resultados("Configuração HSTS", resultados_hsts)

def reconhecimento_dns(alvo):
    mostrar_progresso("Iniciando enumeração DNS...")
    enumerador_dns = EnumeradorDNS()
    resultados_whois = enumerador_dns.obter_info_whois(alvo)
    mostrar_resultados("Informações WHOIS", resultados_whois)
    resultados_dns = enumerador_dns.obter_registros_dns(alvo)
    mostrar_resultados("Registros DNS", resultados_dns)
    resultados_subdominios = enumerador_dns.encontrar_subdominios(alvo)
    mostrar_resultados("Subdomínios Encontrados", resultados_subdominios)
    resultados_zona = enumerador_dns.realizar_transferencia_zona(alvo)
    mostrar_resultados("Resultados da Transferência de Zona", resultados_zona)

def escanear_diretorios(alvo):
    mostrar_progresso("Iniciando escaneamento de diretórios...")
    escaneador_dir = EscaneadorDiretorios()
    resultados = escaneador_dir.escanear_diretorios(alvo)
    if resultados:
        mostrar_resultados("Diretórios e Arquivos Encontrados", {
            'total': len(resultados),
            'itens': resultados
        })
    else:
        mostrar_erro("Nenhum diretório ou arquivo encontrado")

def main():
    mostrar_banner()
    
    while True:
        mostrar_menu_principal()
        escolha = obter_entrada("Escolha uma opção")
        
        if escolha == "1":
            executar_portscan()
        elif escolha == "2":
            alvo = obter_entrada("Digite o alvo (URL ou domínio)")
            reconhecimento_web(alvo)
        elif escolha == "3":
            alvo = obter_entrada("Digite o alvo (domínio)")
            reconhecimento_dns(alvo)
        elif escolha == "4":
            alvo = obter_entrada("Digite o alvo (URL ou domínio)")
            analisador_ssl = AnalisadorSSL()
            resultados = analisador_ssl.obter_info_certificado(alvo)
            mostrar_resultados("Análise SSL/TLS", resultados)
            protocolos = analisador_ssl.verificar_protocolos_ssl(alvo)
            mostrar_resultados("Protocolos Suportados", protocolos)
        elif escolha == "5":
            alvo = obter_entrada("Digite o alvo (URL)")
            escanear_diretorios(alvo)
        elif escolha == "6":
            alvo = obter_entrada("Digite o alvo (URL)")
            detector_waf = DetectorWAF()
            resultados = detector_waf.detectar_waf(alvo)
            mostrar_resultados("Detecção de WAF", resultados)
        elif escolha == "7":
            mostrar_sucesso("Saindo do programa...")
            sys.exit(0)
        else:
            print("Opção inválida!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        mostrar_sucesso("\nPrograma interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        mostrar_erro(f"Erro inesperado: {e}")
        sys.exit(1)