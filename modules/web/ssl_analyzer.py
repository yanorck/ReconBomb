import ssl
import socket
import OpenSSL
from OpenSSL import SSL
import requests
from urllib.parse import urlparse
import urllib3
from datetime import datetime
from typing import Dict, List, Optional
import sys
from config.settings import WEB_TIMEOUT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AnalisadorSSL:
    def __init__(self):
        self.timeout = WEB_TIMEOUT
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Define protocolos baseado na versão do Python
        self.protocolos = {
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.0': ssl.PROTOCOL_TLSv1
        }
        
        # Adiciona TLSv1.3 apenas se estiver disponível (Python 3.7+)
        if sys.version_info >= (3, 7):
            self.protocolos['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3

    def normalizar_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def obter_info_certificado(self, url):
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            
            context = ssl.create_default_context()
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'dominio': dominio,
                        'emissor': dict(x[0] for x in cert['issuer']),
                        'sujeito': dict(x[0] for x in cert['subject']),
                        'validade_inicio': cert['notBefore'],
                        'validade_fim': cert['notAfter'],
                        'versao': cert['version'],
                        'serial': cert['serialNumber'],
                        'algoritmo_assinatura': cert['signatureAlgorithm'],
                        'nomes_alternativos': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return {
                'erro': f'Erro ao obter informações do certificado: {str(e)}'
            }

    def verificar_protocolos_ssl(self, url):
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            resultados = {}
            
            for nome, protocolo in self.protocolos.items():
                try:
                    context = ssl.SSLContext(protocolo)
                    with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                            resultados[nome] = True
                except:
                    resultados[nome] = False
            
            return resultados
        except Exception as e:
            return {
                'erro': f'Erro ao verificar protocolos SSL: {str(e)}'
            }

    def verificar_hsts(self, url):
        try:
            url = self.normalizar_url(url)
            response = requests.get(url, verify=False, allow_redirects=True, timeout=self.timeout)
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            return {
                'hsts_habilitado': bool(hsts_header),
                'max_age': hsts_header.split('max-age=')[1].split(';')[0] if 'max-age=' in hsts_header else None,
                'include_subdomains': 'includeSubDomains' in hsts_header,
                'preload': 'preload' in hsts_header
            }
        except Exception as e:
            return {
                'erro': f'Erro ao verificar HSTS: {str(e)}'
            }

    def verificar_cifras(self, url):
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            
            context = ssl.create_default_context()
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    return {
                        'cifra': ssock.cipher()[0],
                        'versao': ssock.cipher()[1],
                        'bits': ssock.cipher()[2]
                    }
        except Exception as e:
            return {
                'erro': f'Erro ao verificar cifras: {str(e)}'
            }

    def verificar_cadeia_certificados(self, url):
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            
            context = ssl.create_default_context()
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert_chain = ssock.getpeercertchain()
                    return [{
                        'sujeito': dict(x[0] for x in cert['subject']),
                        'emissor': dict(x[0] for x in cert['issuer']),
                        'validade_inicio': cert['notBefore'],
                        'validade_fim': cert['notAfter']
                    } for cert in cert_chain]
        except Exception as e:
            return [{'erro': str(e)}]

    def verificar_ocsp_stapling(self, url):
        try:
            url = self.normalizar_url(url)
            dominio = urlparse(url).netloc
            
            context = ssl.create_default_context()
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    return {
                        'habilitado': bool(ssock.getpeercert(binary_form=True)),
                        'resposta': ssock.getpeercert(binary_form=True) is not None
                    }
        except Exception as e:
            return {'erro': str(e)} 