import socket
import dns.resolver
import dns.zone
import dns.query
import whois
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
import re
from datetime import datetime

class EnumeradorDNS:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
        
        # Lista de servidores DNS públicos
        self.dns_servers = [
            '8.8.8.8',  # Google
            '8.8.4.4',  # Google
            '1.1.1.1',  # Cloudflare
            '1.0.0.1'   # Cloudflare
        ]
        
        # Lista de tipos de registros DNS comuns
        self.tipos_registros = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR']

    def obter_info_whois(self, dominio):
        """
        Obtém informações WHOIS do domínio.
        
        Args:
            dominio: Domínio alvo
            
        Returns:
            Dicionário com informações WHOIS
        """
        try:
            info = whois.whois(dominio)
            return {
                'registrante': info.registrar,
                'data_criacao': info.creation_date,
                'data_expiracao': info.expiration_date,
                'servidores_nome': info.name_servers,
                'status': info.status
            }
        except Exception as e:
            return {'erro': str(e)}

    def obter_registros_dns(self, dominio):
        """
        Obtém registros DNS específicos do domínio.
        
        Args:
            dominio: Domínio alvo
            
        Returns:
            Dicionário com registros encontrados
        """
        resultados = {}
        for tipo in self.tipos_registros:
            try:
                respostas = self.resolver.resolve(dominio, tipo)
                resultados[tipo] = [str(r) for r in respostas]
            except:
                continue
        return resultados

    def encontrar_subdominios(self, dominio):
        """
        Tenta encontrar subdomínios usando força bruta.
        
        Args:
            dominio: Domínio alvo
            
        Returns:
            Lista de subdomínios encontrados
        """
        subdominios = set()
        try:
            respostas = self.resolver.resolve(dominio, 'NS')
            for resposta in respostas:
                servidor = str(resposta)
                try:
                    zona = dns.zone.from_xfr(dns.query.xfr(servidor, dominio))
                    for nome, _ in zona.nodes.items():
                        subdominios.add(f"{nome}.{dominio}")
                except:
                    continue
        except:
            pass
        return list(subdominios)

    def realizar_transferencia_zona(self, dominio):
        """
        Tenta realizar uma transferência de zona DNS.
        
        Args:
            dominio: Domínio alvo
            
        Returns:
            Lista de registros encontrados
        """
        resultados = []
        try:
            respostas = self.resolver.resolve(dominio, 'NS')
            for resposta in respostas:
                servidor = str(resposta)
                try:
                    zona = dns.zone.from_xfr(dns.query.xfr(servidor, dominio))
                    for nome, no in zona.nodes.items():
                        for tipo in self.tipos_registros:
                            try:
                                registros = no.rdatasets.get_rdataset(tipo)
                                if registros:
                                    for registro in registros:
                                        resultados.append({
                                            'nome': f"{nome}.{dominio}",
                                            'tipo': tipo,
                                            'valor': str(registro)
                                        })
                            except:
                                continue
                except:
                    continue
        except:
            pass
        return resultados

    def get_reverse_dns(self, ip: str) -> List[str]:
        """
        Obtém o nome de domínio reverso para um IP.
        
        Args:
            ip: Endereço IP
            
        Returns:
            Lista de nomes de domínio encontrados
        """
        try:
            return socket.gethostbyaddr(ip)
        except socket.herror:
            return [] 