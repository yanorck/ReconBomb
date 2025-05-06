import ssl
import socket
import requests
from urllib.parse import urlparse
import urllib3
from typing import Dict, Optional
import sys
from config.settings import WEB_TIMEOUT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AnalisadorSSL:
    def __init__(self):
        self.timeout = WEB_TIMEOUT
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.protocolos = self._inicializar_protocolos()

    def _inicializar_protocolos(self) -> Dict[str, int]:
        """Define os protocolos SSL/TLS suportados de acordo com a versão do Python"""
        protocolos = {
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1': ssl.PROTOCOL_TLSv1
        }
        
        # Adiciona TLSv1.3 apenas se disponível (Python 3.7+)
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocolos['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
        
        return protocolos

    def normalizar_url(self, url: str) -> str:
        """Garante que a URL tenha o esquema https://"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def obter_info_certificado(self, url: str) -> Dict:
        """Obtém informações do certificado SSL/TLS"""
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            
            # Usa o protocolo TLS mais moderno disponível
            context = ssl.create_default_context()
            
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert = ssock.getpeercert()
                    return self._parse_certificado(cert, dominio)
                    
        except Exception as e:
            return {'erro': f'Falha ao obter certificado: {str(e)}'}

    def _parse_certificado(self, cert: Dict, dominio: str) -> Dict:
        """Processa os dados brutos do certificado"""
        return {
            'dominio': dominio,
            'emissor': dict(x[0] for x in cert.get('issuer', [])),
            'sujeito': dict(x[0] for x in cert.get('subject', [])),
            'validade_inicio': cert.get('notBefore', 'N/A'),
            'validade_fim': cert.get('notAfter', 'N/A'),
            'algoritmo_assinatura': cert.get('signatureAlgorithm', 'N/A'),
            'nomes_alternativos': cert.get('subjectAltName', [])
        }

    def verificar_protocolos_ssl(self, url: str) -> Dict[str, bool]:
        """Verifica quais protocolos SSL/TLS são suportados pelo servidor"""
        resultados = {}
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            
            for nome, protocolo in self.protocolos.items():
                try:
                    context = ssl.SSLContext(protocolo)
                    with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                            resultados[nome] = True
                except Exception:
                    resultados[nome] = False
                    
        except Exception as e:
            resultados['erro'] = str(e)
            
        return resultados

    def verificar_hsts(self, url: str) -> Dict:
        """Verifica se o servidor usa HTTP Strict Transport Security"""
        try:
            url = self.normalizar_url(url)
            response = requests.get(
                url,
                headers=self.headers,
                verify=False,
                allow_redirects=True,
                timeout=self.timeout
            )
            
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            return {
                'habilitado': bool(hsts_header),
                'max_age': self._extrair_max_age(hsts_header),
                'include_subdomains': 'includeSubDomains' in hsts_header,
                'preload': 'preload' in hsts_header
            }
        except Exception as e:
            return {'erro': str(e)}

    def _extrair_max_age(self, hsts_header: str) -> Optional[int]:
        """Extrai o valor max-age do cabeçalho HSTS"""
        try:
            return int(hsts_header.split('max-age=')[1].split(';')[0])
        except (IndexError, ValueError):
            return None

    def verificar_cifras(self, url: str) -> Dict:
        """Obtém informações sobre a cifra SSL em uso"""
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            
            context = ssl.create_default_context()
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cifra = ssock.cipher()
                    return {
                        'cifra': cifra[0],
                        'protocolo': cifra[1],
                        'bits': cifra[2]
                    }
        except Exception as e:
            return {'erro': str(e)}