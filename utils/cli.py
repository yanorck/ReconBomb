import argparse
from ipaddress import ip_address
from modules.web.tech_detector import DetectorTecnologias
from modules.dns.enumerator import EnumeradorDNS
from modules.network.network_scanner import ScannerRede
import ipaddress
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint
import socket
from typing import List, Optional, Dict, Any
from colorama import Fore, Style, init
from tqdm import tqdm
import sys
import os
import time
from utils.port_services import obter_nome_servico

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(description='Scanner de Portas')
    parser.add_argument('alvo', nargs='?', help='Endereço IP ou rede (opcional se executando interativamente)')
    parser.add_argument('--inicio', type=int, default=1, help='Porta inicial')
    parser.add_argument('--fim', type=int, default=1024, help='Porta final')
    parser.add_argument('--protocolo', choices=['tcp', 'udp'], default='tcp', help='Protocolo para escaneamento')
    args = parser.parse_args()
    
    if args.alvo:
        try:
            args.alvo = ip_address(args.alvo)
        except ValueError:
            parser.error("Endereço IP inválido")
        
    return args

def mostrar_banner():
    banner = """
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  ██████╗ ███╗   ███╗██████╗ 
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔═══██╗████╗ ████║██╔══██╗
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╗ ██║   ██║██╔████╔██║██████╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██║   ██║██║╚██╔╝██║██╔══██╗
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝██║ ╚═╝ ██║██████╔╝
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═════╝ 
    =========================================================================
                                   RECONBOMB
                    Ferramenta de Reconhecimento e Escaneamento
    =========================================================================
    """
    print(banner)

def mostrar_progresso(mensagem):
    print(f"\n[*] {mensagem}")

def mostrar_sucesso(mensagem):
    print(f"\n[+] {mensagem}")

def mostrar_erro(mensagem):
    print(f"\n[-] {mensagem}")

def mostrar_resultados(titulo, resultados):
    print(f"\n=== {titulo} ===")
    if isinstance(resultados, dict):
        for chave, valor in resultados.items():
            print(f"{chave}: {valor}")
    elif isinstance(resultados, list):
        for item in resultados:
            print(f"- {item}")
    else:
        print(resultados)
    print("=" * 40)

def mostrar_menu_principal():
    print("\n=== Menu Principal ===")
    print("1. PortScan")
    print("2. Reconhecimento Web")
    print("3. Enumeração DNS")
    print("4. Análise SSL/TLS")
    print("5. Escaneamento de Diretórios")
    print("6. Detecção de WAF")
    print("7. Sair")

def mostrar_menu_escaneamento():
    print("\n=== Menu de Escaneamento de Portas ===")
    print("1. Escanear rede local")
    print("2. Escanear host específico")
    print("3. Escanear portas TCP")
    print("4. Escanear portas UDP")
    print("5. Detectar sistema operacional")
    print("6. Voltar ao menu anterior")

def obter_entrada(mensagem):
    return input(f"\n{mensagem}: ")

def obter_entrada_numerica(mensagem, minimo=1, maximo=None):
    while True:
        try:
            valor = int(input(f"\n{mensagem}: "))
            if maximo and valor > maximo:
                print(f"Por favor, insira um número entre {minimo} e {maximo}")
                continue
            if valor < minimo:
                print(f"Por favor, insira um número maior ou igual a {minimo}")
                continue
            return valor
        except ValueError:
            print("Por favor, insira um número válido")

def obter_entrada_portas(mensagem):
    entrada = input(f"\n{mensagem}: ")
    if not entrada:
        return None
    try:
        return [int(p) for p in entrada.split(",")]
    except ValueError:
        print("Formato inválido. Use números separados por vírgula (ex: 80,443,8080)")
        return None

def limpar_tela():
    os.system('cls' if os.name == 'nt' else 'clear')

def aguardar_tecla():
    input("\nPressione Enter para continuar...")

def display_banner():
    banner = """
    [bold red]RECONBOMB[/bold red] - Ferramenta de Reconhecimento de Segurança
    [italic]Desenvolvido para testes de penetração[/italic]
    """
    console.print(Panel(banner, style="bold blue"))

def display_main_menu() -> int:
    console.print("\n[bold cyan]Menu Principal[/bold cyan]")
    menu = Table(show_header=False, box=None)
    menu.add_row("1", "Escanear rede local")
    menu.add_row("2", "Escanear um host específico")
    menu.add_row("3", "Reconhecimento Web")
    menu.add_row("4", "Enumeração DNS")
    menu.add_row("5", "Análise SSL/TLS")
    menu.add_row("6", "Sair")
    
    console.print(menu)
    
    while True:
        try:
            choice = int(Prompt.ask("\nSelecione uma opção", choices=["1", "2", "3", "4", "5", "6"]))
            return choice
        except ValueError:
            console.print("[red]Opção inválida. Tente novamente.[/red]")

def display_web_menu() -> int:
    console.print("\n[bold cyan]Menu de Reconhecimento Web[/bold cyan]")
    menu = Table(show_header=False, box=None)
    menu.add_row("1", "Detectar Tecnologias Web")
    menu.add_row("2", "Enumerar Diretórios")
    menu.add_row("3", "Detectar WAF")
    menu.add_row("4", "Voltar ao Menu Principal")
    
    console.print(menu)
    
    while True:
        try:
            choice = int(Prompt.ask("\nSelecione uma opção", choices=["1", "2", "3", "4"]))
            return choice
        except ValueError:
            console.print("[red]Opção inválida. Tente novamente.[/red]")

def get_target() -> str:
    target = Prompt.ask("\nDigite o alvo (IP, URL ou domínio)")
    return target.strip()

def display_results(title: str, results: dict):
    console.print(f"\n[bold green]{title}[/bold green]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Item")
    table.add_column("Valor")
    
    for key, value in results.items():
        table.add_row(str(key), str(value))
    
    console.print(table)

def display_error(message: str):
    console.print(f"[bold red]Erro:[/bold red] {message}")

def display_success(message: str):
    console.print(f"[bold green]Sucesso:[/bold green] {message}")

def display_progress(message: str):
    console.print(f"[yellow]{message}[/yellow]")

def confirm_action(message: str) -> bool:
    return Confirm.ask(message)

def display_hosts(hosts: List[str]) -> Optional[str]:
    console.print("\n[bold cyan]Hosts Encontrados:[/bold cyan]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Número")
    table.add_column("IP")
    
    for i, host in enumerate(hosts, 1):
        table.add_row(str(i), host)
    
    console.print(table)
    
    while True:
        try:
            choice = int(Prompt.ask("\nSelecione um host (ou 0 para voltar)", choices=[str(i) for i in range(len(hosts) + 1)]))
            if choice == 0:
                return None
            return hosts[choice - 1]
        except (ValueError, IndexError):
            console.print("[red]Opção inválida. Tente novamente.[/red]")

def encontrar_portas_abertas(ip, porta_inicio=1, porta_fim=65535, protocolo="tcp", max_threads=100):
    scanner = ScannerPortas()
    portas_abertas = {"tcp": [], "udp": []}
    portas = range(porta_inicio, porta_fim + 1)

    try:
        if protocolo in ["tcp", "both"]:
            print(f"Escaneando portas TCP de {porta_inicio} a {porta_fim}...")
            resultados_tcp = scanner.escanear_tcp(ip, portas)
            portas_abertas["tcp"] = [porta for porta, status in resultados_tcp.items() if status == "Aberta"]

        if protocolo in ["udp", "both"]:
            print(f"Escaneando portas UDP de {porta_inicio} a {porta_fim}...")
            resultados_udp = scanner.escanear_udp(ip, portas)
            portas_abertas["udp"] = [porta for porta, status in resultados_udp.items() if status == "Aberta"]

    except KeyboardInterrupt:
        print("\n\nEscaneamento interrompido")
    
    print("\nEscaneamento concluído")
    return portas_abertas

def analisar_host(ip):
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        print(f"Erro: O IP '{ip}' é inválido")
        return

    scanner = ScannerPortas()
    
    while True:
        print("\nOpções disponíveis para análise:")
        print("1. Escanear portas TCP")
        print("2. Escanear portas UDP")
        print("3. Detectar sistema operacional")
        print("4. Encontrar portas abertas")
        print("5. Voltar ao menu principal")
        print("6. Sair do programa")

        try:
            opcao = int(input("\nSelecione uma opção: "))
            if opcao == 1:
                porta_inicio = int(input("Porta inicial: "))
                porta_fim = int(input("Porta final: "))
                print(f"\nEscaneando {ip} de {porta_inicio} a {porta_fim} usando TCP...")
                portas = range(porta_inicio, porta_fim + 1)
                try:
                    resultados = scanner.escanear_tcp(ip, portas)
                    fechadas = 0
                    total = 0
                    for porta, status in resultados.items():
                        if status == "Aberta":
                            servico = scanner.obter_servico(porta)
                            print(f"Porta {porta}: {status} - {servico}")
                        else:
                            fechadas += 1
                        total += 1
                    print(f"Das {total} portas TCP, {fechadas} estão fechadas ou filtradas e {total - fechadas} abertas")
                except KeyboardInterrupt:
                    print("\nEscaneamento TCP interrompido")
                    continue

            elif opcao == 2:
                porta_inicio = int(input("Porta inicial: "))
                porta_fim = int(input("Porta final: "))
                print(f"\nEscaneando {ip} de {porta_inicio} a {porta_fim} usando UDP...")
                portas = range(porta_inicio, porta_fim + 1)
                try:
                    resultados = scanner.escanear_udp(ip, portas)
                    fechadas = 0
                    total = 0
                    for porta, status in resultados.items():
                        if status == "Aberta":
                            servico = scanner.obter_servico(porta)
                            print(f"Porta {porta}: {status} - {servico}")
                        else:
                            fechadas += 1
                        total += 1
                    print(f"Das {total} portas UDP, {fechadas} estão fechadas ou filtradas e {total - fechadas} abertas")
                except KeyboardInterrupt:
                    print("\nEscaneamento UDP interrompido")
                    continue

            elif opcao == 3:
                try:
                    resultado = scanner.detectar_os(ip)
                    if resultado['status'] == 'sucesso':
                        print(f"\nSistema operacional detectado: {resultado['os']}")
                        print(f"Detalhes: {resultado['detalhes']}")
                    else:
                        print(f"\nErro: {resultado['mensagem']}")
                except KeyboardInterrupt:
                    print("\n\nDetecção de SO interrompida")
                    continue

            elif opcao == 4:
                try:
                    print("\nSubopções para encontrar portas abertas:")
                    print("1. Analisar todas as portas (1-65535)")
                    print("2. Especificar um intervalo de portas")
                    print("3. Analisar as portas mais utilizadas (Well-Known Ports)")
                    subopcao = int(input("Selecione uma subopção: "))
                    if subopcao == 1:
                        print(f"\nProcurando portas abertas no host {ip}...")
                        portas_abertas = encontrar_portas_abertas(ip, porta_inicio=1, porta_fim=65535)
                        if portas_abertas["tcp"] or portas_abertas["udp"]:
                            print("Portas abertas encontradas:")
                            if portas_abertas["tcp"]:
                                print("TCP:")
                                for porta in portas_abertas["tcp"]:
                                    servico = scanner.obter_servico(porta)
                                    print(f"  Porta {porta}: {servico}")
                            if portas_abertas["udp"]:
                                print("UDP:")
                                for porta in portas_abertas["udp"]:
                                    servico = scanner.obter_servico(porta)
                                    print(f"  Porta {porta}: {servico}")
                        else:
                            print("Nenhuma porta aberta encontrada.")
                    elif subopcao == 2:
                        porta_inicio = int(input("Porta inicial: "))
                        porta_fim = int(input("Porta final: "))
                        print(f"\nProcurando portas abertas no host {ip} no intervalo {porta_inicio}-{porta_fim}...")
                        portas_abertas = encontrar_portas_abertas(ip, porta_inicio, porta_fim)
                        if portas_abertas["tcp"] or portas_abertas["udp"]:
                            print("Portas abertas encontradas:")
                            if portas_abertas["tcp"]:
                                print("TCP:")
                                for porta in portas_abertas["tcp"]:
                                    servico = scanner.obter_servico(porta)
                                    print(f"  Porta {porta}: {servico}")
                            if portas_abertas["udp"]:
                                print("UDP:")
                                for porta in portas_abertas["udp"]:
                                    servico = scanner.obter_servico(porta)
                                    print(f"  Porta {porta}: {servico}")
                        else:
                            print("Nenhuma porta aberta encontrada.")
                    elif subopcao == 3:
                        print(f"\nAnalisando as portas mais utilizadas (Well-Known Ports) no host {ip}...")
                        portas_abertas = encontrar_portas_abertas(ip, porta_inicio=1, porta_fim=1024)
                        if portas_abertas["tcp"] or portas_abertas["udp"]:
                            print("Portas abertas encontradas:")
                            if portas_abertas["tcp"]:
                                print("TCP:")
                                for porta in portas_abertas["tcp"]:
                                    servico = scanner.obter_servico(porta)
                                    print(f"  Porta {porta}: {servico}")
                            if portas_abertas["udp"]:
                                print("UDP:")
                                for porta in portas_abertas["udp"]:
                                    servico = scanner.obter_servico(porta)
                                    print(f"  Porta {porta}: {servico}")
                        else:
                            print("Nenhuma porta aberta encontrada nas Well-Known Ports")
                    else:
                        print("Subopção inválida. Tente novamente")
                except KeyboardInterrupt:
                    print("\n\nEscaneamento de portas interrompido")
                    continue

            elif opcao == 5:
                print("Voltando ao menu principal...")
                break

            elif opcao == 6:
                print("Saindo do programa...")
                exit()

            else:
                print("Opção inválida. Tente novamente")

        except ValueError:
            print("Entrada inválida. Digite um número")