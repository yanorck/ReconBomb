import socket
import dns.resolver
import dns.zone
import dns.query
import whois
from typing import Dict, List, Optional, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from datetime import datetime
from urllib.parse import urlparse
import requests
import json

class EnumeradorDNS:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 10
        
        # Servidores DNS públicos com fallback
        self.dns_servers = [
            '8.8.8.8',  # Google
            '1.1.1.1',  # Cloudflare
            '9.9.9.9',   # Quad9
            '208.67.222.222'  # OpenDNS
        ]
        self.resolver.nameservers = self.dns_servers
        
        # Tipos de registros DNS para consulta
        self.tipos_registros = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        # Lista de subdomínios comuns para força bruta
        self.subdominios_comuns = [
            'www', 'mail', 'ftp', 'admin', 'webmail',
            'smtp', 'pop', 'imap', 'test', 'dev'
        ]

    def _extrair_dominio(self, url: str) -> str:
        """Extrai o domínio principal de uma URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        dominio = parsed.netloc
        return '.'.join(dominio.split('.')[-2:]) if dominio else url

    def obter_info_whois(self, dominio: str) -> Dict:
        """Consulta WHOIS com suporte especial para domínios .br"""
        dominio_limpo = self._extrair_dominio_para_whois(dominio)
        
        # Caso especial para domínios .br
        if dominio_limpo.endswith('.br'):
            return self._consultar_whois_br(dominio_limpo)
            
        try:
            # Consulta WHOIS padrão para outros domínios
            info = whois.whois(dominio_limpo)
            return self._parse_whois_data(info, dominio_limpo)
        except Exception as e:
            return {
                'dominio': dominio_limpo,
                'erro': 'Falha na consulta WHOIS',
                'detalhes': str(e)
            }

    def _consultar_whois_br(self, dominio: str) -> Dict:
        """Consulta especializada para domínios brasileiros usando a API do Registro.br"""
        try:
            url = f"https://rdap.registro.br/domain/{dominio}"
            response = requests.get(url, timeout=10)
            data = response.json()
            
            return {
                'dominio': dominio,
                'registrante': data.get('registrant', {}).get('name', 'N/A'),
                'data_criacao': self._formatar_data_br(data.get('events', [{}])[0].get('eventDate')),
                'data_expiracao': self._formatar_data_br(next(
                    (e['eventDate'] for e in data.get('events', [])
                    if e.get('eventAction') == 'expiration'), None)),
                'servidores_nome': [ns['ldhName'] for ns in data.get('nameservers', [])],
                'status': [s.split(':')[-1] for s in data.get('status', [])],
                'ultimo_atualizado': self._formatar_data_br(data.get('lastChangedDate')),
                'fonte': 'Registro.br RDAP'
            }
        except Exception as e:
            return {
                'dominio': dominio,
                'erro': 'Falha na consulta ao Registro.br',
                'detalhes': str(e)
            }

    def _formatar_data_br(self, data_str: Optional[str]) -> Optional[str]:
        """Formata datas no padrão do Registro.br"""
        if not data_str:
            return None
        try:
            dt = datetime.strptime(data_str.split('T')[0], '%Y-%m-%d')
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return data_str

    def _extrair_dominio_para_whois(self, url: str) -> str:
        """Versão melhorada para domínios .br"""
        dominio = url.split('://')[-1].split('/')[0].lower()
        
        # Caso especial para .edu.br, .gov.br, etc.
        if dominio.endswith('.edu.br'):
            return dominio
        if dominio.endswith('.br') and len(dominio.split('.')) > 2:
            return dominio
        return dominio

    def _consultar_registro_dns(self, dominio: str, tipo: str) -> List[str]:
        """Consulta um tipo específico de registro DNS com fallback"""
        try:
            respostas = self.resolver.resolve(dominio, tipo)
            return [str(r) for r in respostas]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except dns.resolver.Timeout:
            # Tentar com outro servidor DNS
            for server in self.dns_servers:
                try:
                    temp_resolver = dns.resolver.Resolver()
                    temp_resolver.nameservers = [server]
                    respostas = temp_resolver.resolve(dominio, tipo)
                    return [str(r) for r in respostas]
                except:
                    continue
            return []
        except Exception:
            return []

    def obter_registros_dns(self, dominio: str) -> Dict[str, List[str]]:
        """Obtém múltiplos registros DNS com paralelismo"""
        dominio = self._extrair_dominio(dominio)
        resultados = {}
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self._consultar_registro_dns, dominio, tipo): tipo
                for tipo in self.tipos_registros
            }
            
            for future in as_completed(futures):
                tipo = futures[future]
                resultados[tipo] = future.result()
        
        # Remove tipos de registro vazios
        return {k: v for k, v in resultados.items() if v}

    def _testar_subdominio(self, dominio: str, sub: str) -> Optional[str]:
        """Testa se um subdomínio existe"""
        full_domain = f"{sub}.{dominio}"
        try:
            # Verifica registros A e AAAA
            if self._consultar_registro_dns(full_domain, 'A') or \
               self._consultar_registro_dns(full_domain, 'AAAA'):
                return full_domain
        except:
            return None
        return None

    def encontrar_subdominios(self, dominio: str) -> List[str]:
        """Encontra subdomínios usando força bruta paralelizada"""
        dominio = self._extrair_dominio(dominio)
        subdominios = set()
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(self._testar_subdominio, dominio, sub)
                for sub in self.subdominios_comuns
            ]
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdominios.add(result)
        
        # Tentar transferência de zona como fallback
        try:
            respostas = self.resolver.resolve(dominio, 'NS')
            for resposta in respostas:
                try:
                    zona = dns.zone.from_xfr(dns.query.xfr(str(resposta), dominio))
                    subdominios.update(f"{nome}.{dominio}" for nome in zona.nodes.keys())
                except:
                    continue
        except:
            pass
        
        return sorted(subdominios)

    def realizar_transferencia_zona(self, dominio: str) -> List[Dict[str, str]]:
        """Tenta realizar transferência de zona DNS"""
        dominio = self._extrair_dominio(dominio)
        resultados = []
        
        try:
            # Obter servidores de nomes
            ns_servers = self._consultar_registro_dns(dominio, 'NS')
            if not ns_servers:
                return []
            
            for server in ns_servers:
                try:
                    # Tentar transferência de zona AXFR
                    zona = dns.zone.from_xfr(dns.query.xfr(server, dominio))
                    for nome, no in zona.nodes.items():
                        for tipo in self.tipos_registros:
                            try:
                                registros = no.get_rdataset(dns.rdataclass.IN, dns.rdatatype.from_text(tipo))
                                if registros:
                                    for registro in registros:
                                        resultados.append({
                                            'nome': f"{nome}.{dominio}",
                                            'tipo': tipo,
                                            'valor': str(registro)
                                        })
                            except:
                                continue
                except Exception as e:
                    continue
        
        except Exception as e:
            pass
        
        return resultados

    def get_reverse_dns(self, ip: str) -> List[str]:
        """Consulta DNS reverso para um IP"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return [hostname] if hostname else []
        except (socket.herror, socket.gaierror):
            return []
        except Exception:
            return []