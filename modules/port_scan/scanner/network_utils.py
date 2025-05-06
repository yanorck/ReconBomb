import socket
import nmap
from concurrent.futures import ThreadPoolExecutor

def create_socket(ip_version, protocol):
    if ip_version == 6:
        family = socket.AF_INET6
    else:
        family = socket.AF_INET
    
    if protocol.lower() == 'udp':
        sock_type = socket.SOCK_DGRAM
    else:
        sock_type = socket.SOCK_STREAM
        
    return socket.socket(family, sock_type)

def discover_hosts(network):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=network, arguments='-sn')
        
        active_hosts = []
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                active_hosts.append(host)
        
        return active_hosts
    except KeyboardInterrupt:
        print("\nEscaneamento de rede interrompido")
        return []