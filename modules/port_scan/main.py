from utils.cli import display_menu, analyze_host
from scanner.network_utils import discover_hosts
import socket

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"Erro ao obter o IP local: {e}")
        return None
    
def resolve_target(target):
    try:
        if target.startswith("http://"):
            target = target[len("http://"):]
        elif target.startswith("https://"):
            target = target[len("https://"):]

        if target.endswith("/"):
            target = target[:-1]

        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"Erro: Não foi possível resolver o endereço '{target}', verifique se não ta errado")
        return None

def main():
    while True:
        print("\nMenu Principal:")
        print("1. Escanear rede local")
        print("2. Escanear um host específico (IP ou URL)")
        print("3. Sair do programa")

        try:
            option = int(input("\nSelecione uma opção: "))
            if option == 1:
                local_ip = get_local_ip()
                if not local_ip:
                    print("Não foi possível determinar o IP local")
                    continue

                network = f"{local_ip.rsplit('.', 1)[0]}.0/24"
                print(f"Detectado IP local: {local_ip}")
                print(f"Escaneando a rede {network} para encontrar hosts ativos...")
                active_hosts = discover_hosts(network)
                if not active_hosts:
                    print("Nenhum host ativo encontrado na rede")
                    continue

                selected_ip = display_menu(active_hosts)
                if not selected_ip:
                    print("Saindo...")
                    break

                analyze_host(selected_ip)

            elif option == 2:
                target = input("Digite o IP ou URL do host (ex.: https://ensino.hashi.pro.br/): ").strip()
                ip = resolve_target(target)
                if not ip:
                    print(f"Não foi possível resolver o endereço: {target}")
                    continue

                print(f"Endereço resolvido: {ip}")
                analyze_host(ip)

            elif option == 3:
                print("Saindo do programa...")
                break

            else:
                print("Opção inválida. Tente novamente")
        except ValueError:
            print("Entrada inválida. Digite um número!")

if __name__ == "__main__":
    main()