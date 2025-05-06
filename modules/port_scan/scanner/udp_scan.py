import socket
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

def udp_scan(ip, ports, max_threads=100):
    results = {}

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.5)
                s.sendto(b"", (str(ip), port))
                try:
                    data, _ = s.recvfrom(1024)
                    results[port] = "Open" if data else "Closed"
                except socket.timeout:
                    results[port] = "Open" # Ver com professor se timeout pode considerar aberta
        except Exception:
            results[port] = "Filtered"

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            list(tqdm(executor.map(scan_port, ports), total=len(ports), desc="Escaneando UDP"))
    except KeyboardInterrupt:
        print("\nEscaneamento UDP interrompid")
    
    return results