import socket
# A fazer : conseguir pegar banner de https (porta 443)

def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(10)
            s.connect((str(ip), port))

            if port == 80 or port == 8080:  # Servidor HTTP , ficava dando timeout
                s.sendall(b"GET / HTTP/1.1\r\nHost: " + str(ip).encode() + b"\r\n\r\n")

            banner = s.recv(1024).decode().strip()
            return banner
    except socket.timeout:
        print(f"Erro ao capturar banner na porta {port}: Timeout")
    except Exception as e:
        print(f"Erro ao capturar banner na porta {port}: {e}")
    return None