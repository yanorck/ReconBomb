import socket
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from utils.port_services import get_service_name

def tcp_scan(ip, ports, max_threads=100):
    results = {}
    
    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    results[port] = "Open"
                    service = get_service_name(port)
                    # Usa tqdm.write para evitar conflito com a barra de progresso, print buga tudo
                    tqdm.write(f"Porta {port}: Open - {service}")
                else:
                    results[port] = "Closed"
        except Exception:
            results[port] = "Filtered"

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            list(tqdm(executor.map(scan_port, ports), total=len(ports), desc="Escaneando TCP"))
    except KeyboardInterrupt:
        print("\nEscaneamento TCP interrompido")
    
    return results