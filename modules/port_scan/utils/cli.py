import argparse
from ipaddress import ip_address
from scanner.tcp_scan import tcp_scan
from scanner.udp_scan import udp_scan
from scanner.os_detection import grab_banner
from utils.port_services import get_service_name
import ipaddress

def parse_args():
    parser = argparse.ArgumentParser(description='Port Scanner')
    parser.add_argument('target', nargs='?', help='IP address or network (optional if running interactively)')
    parser.add_argument('--start', type=int, default=1, help='Start port')
    parser.add_argument('--end', type=int, default=1024, help='End port')
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help='Protocol to use for scanning')
    args = parser.parse_args()
    
    if args.target:
        try:
            args.target = ip_address(args.target)
        except ValueError:
            parser.error("Invalid IP address")
        
    return args

def display_menu(hosts):
    print("\nHosts ativos na rede:")
    for idx, host in enumerate(hosts, start=1):
        print(f"{idx}. {host}")
    
    while True:
        try:
            choice = int(input("\nSelecione o número do host que deseja analisar (ou 0 para sair): "))
            if choice == 0:
                return None
            elif 1 <= choice <= len(hosts):
                return hosts[choice - 1]
            else:
                print("Escolha inválida. Tente novamente")
        except ValueError:
            print("Entrada inválida. Digite um número")


def find_open_ports(ip, start_port=1, end_port=65535, protocol="tcp", max_threads=100):
    open_ports = {"tcp": [], "udp": []}
    ports = range(start_port, end_port + 1)

    try:
        if protocol in ["tcp", "both"]:
            print(f"Escaneando portas TCP de {start_port} a {end_port}...")
            tcp_results = tcp_scan(ip, ports, max_threads)
            open_ports["tcp"] = [port for port, status in tcp_results.items() if status == "Open"]

        if protocol in ["udp", "both"]:
            print(f"Escaneando portas UDP de {start_port} a {end_port}...")
            udp_results = udp_scan(ip, ports, max_threads)
            open_ports["udp"] = [port for port, status in udp_results.items() if status == "Open"]

    except KeyboardInterrupt:
        print("\n\nEscaneamento interrompido")
    
    print("\nEscaneamento concluído")
    return open_ports

def analyze_host(ip):
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        print(f"Erro: O IP '{ip}' é inválido")
        return

    while True:
        print("\nOpções disponíveis para análise:")
        print("1. Escanear portas TCP")
        print("2. Escanear portas UDP")
        print("3. Detectar sistema operacional via banner grabbing")
        print("4. Encontrar portas abertas")
        print("5. Voltar ao menu principal")
        print("6. Sair do programa")

        try:
            option = int(input("\nSelecione uma opcao: "))
            if option == 1:
                start_port = int(input("Porta inicial: "))
                end_port = int(input("Porta final: "))
                print(f"\nEscaneando {ip} de {start_port} a {end_port} usando TCP...")
                ports = range(start_port, end_port + 1)
                try:
                    results = tcp_scan(ip, ports)
                    fechadas = 0
                    total = 0
                    for port, status in results.items():
                        if status == "Open":
                            service = get_service_name(port)
                            banner = grab_banner(ip, port)
                            print(f"Porta {port}: {status} - {service}")
                            if banner:
                                print(f"  Banner: {banner}")

                        else:
                            fechadas +=1
                        total +=1
                    print(f"Das {total} portas TCP, {fechadas} estão fechadas ou filtered e {total - fechadas} abertas")
                except KeyboardInterrupt:
                    print("\nEscaneamento TCP interrompido")
                    continue

            elif option == 2:
                start_port = int(input("Porta inicial: "))
                end_port = int(input("Porta final: "))
                print(f"\nEscaneando {ip} de {start_port} a {end_port} usando UDP...")
                ports = range(start_port, end_port + 1)
                try:
                    results = udp_scan(ip, ports)
                    fechadas = 0
                    total = 0
                    for port, status in results.items():
                        if status == "Open":
                            service = get_service_name(port)
                            print(f"Porta {port}: {status} - {service}")
                        else:
                            fechadas += 1
                        total +=1
                    print(f"Das {total} portas UDP, {fechadas} estão fechadas ou filtered e {total - fechadas} abertas")
                except KeyboardInterrupt:
                    print("\nEscaneamento UDP interrompido")
                    continue

            elif option == 3:
                try:
                    port = int(input("Porta para detecção de SO via banner grabbing: "))
                    banner = grab_banner(ip, port)
                    if banner:
                        print(f"Banner da porta {port}: {banner}")
                    else:
                        print(f"Nenhum banner detectado na porta {port}.")
                except KeyboardInterrupt:
                    print("\n\nDetecção de SO via banner grabbing interrompida")
                    continue

            elif option == 4:
                try:
                    print("\nSubopções para encontrar portas abertas:")
                    print("1. Analisar todas as portas (1-65535)")
                    print("2. Especificar um intervalo de portas")
                    print("3. Analisar as portas mais utilizadas (Well-Known Ports)")
                    suboption = int(input("Selecione uma subopção: "))
                    if suboption == 1:
                        print(f"\nProcurando portas abertas no host {ip}...")
                        open_ports = find_open_ports(ip, start_port=1, end_port=65535)
                        if open_ports["tcp"] or open_ports["udp"]:
                            print("Portas abertas encontradas:")
                            if open_ports["tcp"]:
                                print("TCP:")
                                for port in open_ports["tcp"]:
                                    service = get_service_name(port)
                                    print(f"  Porta {port}: {service}")
                            if open_ports["udp"]:
                                print("UDP:")
                                for port in open_ports["udp"]:
                                    service = get_service_name(port)
                                    print(f"  Porta {port}: {service}")
                        else:
                            print("Nenhuma porta aberta encontrada.")
                    elif suboption == 2:
                        start_port = int(input("Porta inicial: "))
                        end_port = int(input("Porta final: "))
                        print(f"\nProcurando portas abertas no host {ip} no intervalo {start_port}-{end_port}...")
                        open_ports = find_open_ports(ip, start_port, end_port)
                        if open_ports["tcp"] or open_ports["udp"]:
                            print("Portas abertas encontradas:")
                            if open_ports["tcp"]:
                                print("TCP:")
                                for port in open_ports["tcp"]:
                                    service = get_service_name(port)
                                    print(f"  Porta {port}: {service}")
                            if open_ports["udp"]:
                                print("UDP:")
                                for port in open_ports["udp"]:
                                    service = get_service_name(port)
                                    print(f"  Porta {port}: {service}")
                        else:
                            print("Nenhuma porta aberta encontrada.")
                    elif suboption == 3:
                        print(f"\nAnalisando as portas mais utilizadas (Well-Known Ports) no host {ip}...")
                        open_ports = find_open_ports(ip, start_port=1, end_port=1024)
                        if open_ports["tcp"] or open_ports["udp"]:
                            print("Portas abertas encontradas:")
                            if open_ports["tcp"]:
                                print("TCP:")
                                for port in open_ports["tcp"]:
                                    service = get_service_name(port)
                                    print(f"  Porta {port}: {service}")
                            if open_ports["udp"]:
                                print("UDP:")
                                for port in open_ports["udp"]:
                                    service = get_service_name(port)
                                    print(f"  Porta {port}: {service}")
                        else:
                            print("Nenhuma porta aberta encontrada nas Well-Known Ports")
                    else:
                        print("Subopção inválida. Tente novamente")
                except KeyboardInterrupt:
                    print("\n\nEscaneamento de portas interrompido")
                    continue

            elif option == 5:
                print("Voltando ao menu principal...")
                break

            elif option == 6:
                print("Saindo do programa...")
                exit()

            else:
                print("Opção inválida. Tente novamente")

        except ValueError:
            print("Entrada inválida. Digite um número")