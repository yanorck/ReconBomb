from utils.cli import (
    mostrar_banner, mostrar_menu_principal, mostrar_menu_escaneamento,
    obter_entrada, mostrar_resultados, mostrar_erro, mostrar_sucesso,
    mostrar_progresso, display_hosts
)
from modules.port_scan import ScannerPortas, descobrir_hosts
from modules.web.tech_detector import DetectorTecnologias
from modules.web.waf_detector import DetectorWAF
from modules.web.ssl_analyzer import AnalisadorSSL
from modules.web.dir_scanner import EscaneadorDiretorios
from modules.dns.enumerator import EnumeradorDNS
from modules.network.network_scanner import ScannerRede
import socket
import sys
import urllib3
import json
import os
from datetime import datetime
from colorama import Fore, Style, init
import pygame
import time
import re
from urllib.parse import unquote, urlparse
import requests
from tqdm import tqdm
import threading
import select

init()
pygame.mixer.init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ARQUIVO_HISTORICO = "url_history.json"
DIRETORIO_MUSICA = "assets/music"
DIRETORIO_ASCII = "assets/ascii"

musica_atual = None
thread_musica = None
musica_tocando = False
controle_musica = {
    'tocando': False,
    'pausada': False,
    'parar': False
}

def thread_controle_musica():
    global musica_tocando, musica_atual
    while not controle_musica['parar']:
        if controle_musica['tocando'] and not controle_musica['pausada']:
            if not pygame.mixer.music.get_busy() and musica_atual:
                proxima_musica()
        time.sleep(0.1)

def iniciar_controle_musica():
    global thread_musica
    if not thread_musica or not thread_musica.is_alive():
        thread_musica = threading.Thread(target=thread_controle_musica, daemon=True)
        thread_musica.start()

def parar_controle_musica():
    global controle_musica
    controle_musica['parar'] = True
    if thread_musica and thread_musica.is_alive():
        thread_musica.join(timeout=1)

def tocar_musica(caminho_arquivo):
    try:
        pygame.mixer.music.load(caminho_arquivo)
        pygame.mixer.music.play(-1)
        musica_atual = caminho_arquivo
        controle_musica['tocando'] = True
        controle_musica['pausada'] = False
        return True
    except Exception as e:
        mostrar_erro(f"Erro ao tocar música: {e}")
        return False

def pausar_musica():
    global controle_musica
    if controle_musica['tocando']:
        if controle_musica['pausada']:
            pygame.mixer.music.unpause()
            controle_musica['pausada'] = False
            print("Música retomada")
        else:
            pygame.mixer.music.pause()
            controle_musica['pausada'] = True
            print("Música pausada")

def parar_musica():
    global controle_musica
    pygame.mixer.music.stop()
    controle_musica['tocando'] = False
    controle_musica['pausada'] = False
    print("Música parada")

def proxima_musica():
    global musica_atual, lista_musicas, indice_atual
    if lista_musicas:
        indice_atual = (indice_atual + 1) % len(lista_musicas)
        nome, url = lista_musicas[indice_atual]
        print(f"\nTocando: {nome}")
        caminho_local = baixar_musica(url)
        if caminho_local:
            tocar_musica(caminho_local)

def musica_anterior():
    global musica_atual, lista_musicas, indice_atual
    if lista_musicas:
        indice_atual = (indice_atual - 1) % len(lista_musicas)
        nome, url = lista_musicas[indice_atual]
        print(f"\nTocando: {nome}")
        caminho_local = baixar_musica(url)
        if caminho_local:
            tocar_musica(caminho_local)

def mostrar_controles_musica():
    print("\nControles de Música:")
    print("P - Pausar/Retomar")
    print("S - Parar")
    print("N - Próxima música")
    print("B - Música anterior")
    print("M - Mostrar este menu")
    print("Q - Voltar ao menu principal")

def tratar_comando_musica(cmd):
    cmd = cmd.lower()
    if cmd == 'p':
        pausar_musica()
    elif cmd == 's':
        parar_musica()
    elif cmd == 'n':
        proxima_musica()
    elif cmd == 'b':
        musica_anterior()
    elif cmd == 'm':
        mostrar_controles_musica()
    elif cmd == 'q':
        parar_musica()
        return False
    return True

def garantir_diretorios():
    os.makedirs(DIRETORIO_MUSICA, exist_ok=True)
    os.makedirs(DIRETORIO_ASCII, exist_ok=True)

def baixar_musica(url):
    caminho_local = obter_caminho_musica_local(url)
    if os.path.exists(caminho_local):
        return caminho_local
    print(f"\nBaixando música: {extrair_nome_musica(url)}")
    if baixar_musica(url, caminho_local):
        return caminho_local
    return None

def obter_caminho_musica_local(url):
    nome_arquivo = os.path.basename(urlparse(url).path)
    if not nome_arquivo:
        nome_arquivo = f"musica_{hash(url)}.mp3"
    return os.path.join(DIRETORIO_MUSICA, nome_arquivo)

def extrair_nome_musica(url):
    url = unquote(url)
    nome = os.path.splitext(os.path.basename(url))[0]
    nome = nome.replace('_', ' ').replace('-', ' ')
    nome = re.sub(r'[^\w\s-]', '', nome)
    nome = ' '.join(palavra.capitalize() for palavra in nome.split())
    return nome if nome else "Música Desconhecida"

def mostrar_ascii_mestre():
    try:
        with open('mestre.txt', 'r') as f:
            ascii_art = f.read()
            print(Fore.CYAN + ascii_art + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.YELLOW + "Arquivo mestre.txt não encontrado" + Style.RESET_ALL)

def obter_ip_local():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        mostrar_erro(f"Erro ao obter o IP local: {e}")
        return None

def resolver_alvo(alvo):
    try:
        if alvo.startswith("http://"):
            alvo = alvo[len("http://"):]
        elif alvo.startswith("https://"):
            alvo = alvo[len("https://"):]
        if alvo.endswith("/"):
            alvo = alvo[:-1]
        ip = socket.gethostbyname(alvo)
        return ip
    except socket.gaierror:
        mostrar_erro(f"Não foi possível resolver o endereço '{alvo}'")
        return None

def escanear_rede():
    ip_local = obter_ip_local()
    if not ip_local:
        return
    rede = f"{ip_local.rsplit('.', 1)[0]}.0/24"
    mostrar_progresso(f"Detectado IP local: {ip_local}")
    mostrar_progresso(f"Escaneando a rede {rede} para encontrar hosts ativos...")
    hosts_ativos = descobrir_hosts(rede)
    if not hosts_ativos:
        mostrar_erro("Nenhum host ativo encontrado na rede")
        return
    ip_selecionado = display_hosts(hosts_ativos)
    if not ip_selecionado:
        return
    return ip_selecionado

def escanear_portas():
    scanner = ScannerPortas()
    
    while True:
        mostrar_menu_escaneamento()
        
        escolha = obter_entrada("Escolha uma opção")
        
        if escolha == "1":
            rede = obter_entrada("Digite a rede (ex: 192.168.1.0/24) ou pressione Enter para rede local")
            hosts = scanner.escanear_rede(rede if rede else None)
            print("\nHosts ativos encontrados:")
            for host in hosts:
                print(f"- {host}")
        
        elif escolha == "2":
            host = obter_entrada("Digite o IP ou hostname")
            portas = scanner.escanear_portas(host)
            print(f"\nPortas abertas em {host}:")
            for porta in portas:
                servico = scanner.obter_servico(porta)
                print(f"- Porta {porta} ({servico})")
        
        elif escolha == "3":
            host = obter_entrada("Digite o IP ou hostname")
            portas = obter_entrada("Digite as portas (ex: 80,443,8080) ou pressione Enter para portas comuns")
            portas = [int(p) for p in portas.split(",")] if portas else None
            resultados = scanner.escanear_tcp(host, portas)
            print(f"\nResultados do scan TCP em {host}:")
            for porta, status in resultados.items():
                print(f"- Porta {porta}: {status}")
        
        elif escolha == "4":
            host = obter_entrada("Digite o IP ou hostname")
            portas = obter_entrada("Digite as portas (ex: 53,123,161) ou pressione Enter para portas comuns")
            portas = [int(p) for p in portas.split(",")] if portas else None
            resultados = scanner.escanear_udp(host, portas)
            print(f"\nResultados do scan UDP em {host}:")
            for porta, status in resultados.items():
                print(f"- Porta {porta}: {status}")
        
        elif escolha == "5":
            host = obter_entrada("Digite o IP ou hostname")
            resultado = scanner.detectar_os(host)
            if resultado['status'] == 'sucesso':
                print(f"\nSistema operacional detectado: {resultado['os']}")
                print(f"Detalhes: {resultado['detalhes']}")
            else:
                print(f"\nErro: {resultado['mensagem']}")
        
        elif escolha == "6":
            return
        
        else:
            print("Opção inválida!")

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

def relaxar_com_musica():
    print("\n=== Relaxamento com Música ===")
    print("1. Música Calma")
    print("2. Sons da Natureza")
    print("3. Voltar ao menu principal")
    
    escolha = input("\nEscolha uma opção: ")
    
    if escolha == "1":
        url_musica = "https://example.com/calm_music.mp3"
        caminho_musica = "assets/music/calm_music.mp3"
        
        if not os.path.exists(caminho_musica):
            if not baixar_musica(url_musica):
                print("Não foi possível baixar a música.")
                return
        
        tocar_musica(caminho_musica)
        print("\nMúsica tocando... Pressione Ctrl+C para parar.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pygame.mixer.music.stop()
            print("\nMúsica parada.")
    
    elif escolha == "2":
        url_musica = "https://example.com/nature_sounds.mp3"
        caminho_musica = "assets/music/nature_sounds.mp3"
        
        if not os.path.exists(caminho_musica):
            if not baixar_musica(url_musica):
                print("Não foi possível baixar a música.")
                return
        
        tocar_musica(caminho_musica)
        print("\nSons da natureza tocando... Pressione Ctrl+C para parar.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pygame.mixer.music.stop()
            print("\nMúsica parada.")

def main():
    garantir_diretorios()
    mostrar_ascii_mestre()
    mostrar_banner()
    iniciar_controle_musica()
    
    while True:
        mostrar_menu_principal()
        escolha = obter_entrada("Escolha uma opção")
        
        if escolha == "1":
            escanear_portas()
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
            relaxar_com_musica()
        elif escolha == "8":
            parar_controle_musica()
            mostrar_sucesso("Saindo do programa...")
            sys.exit(0)
        else:
            print("Opção inválida!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        parar_controle_musica()
        mostrar_sucesso("\nPrograma interrompido pelo usuário")
        sys.exit(0)
    except Exception as e:
        mostrar_erro(f"Erro inesperado: {e}")
        sys.exit(1)