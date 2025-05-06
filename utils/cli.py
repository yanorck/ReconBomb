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
