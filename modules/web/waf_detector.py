import requests
import re
from typing import Dict, List, Optional
import urllib3
from config.settings import USER_AGENT, WEB_TIMEOUT

# Desativa avisos de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DetectorWAF:
    def __init__(self):
        self.timeout = WEB_TIMEOUT
        self.user_agent = USER_AGENT
        self.assinaturas_waf = self._carregar_assinaturas()
        self.payloads = self._carregar_payloads()

    def _carregar_assinaturas(self) -> Dict:
        """Carrega assinaturas de WAFs"""
        return {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'server', 'cloudflare'],
                'cookies': ['__cfduid', 'cf_clearance', '__cf_bm'],
                'body': ['cloudflare-nginx', 'cloudflare', 'attention required!'],
                'patterns': [r'cloudflare.*ray id', r'error.*cloudflare']
            },
            'ModSecurity': {
                'headers': ['mod_security', 'NOYB'],
                'body': ['ModSecurity', 'Mod_Security', 'NOYB'],
                'patterns': [r'ModSecurity.*denied', r'not acceptable']
            },
            'Akamai': {
                'headers': ['X-Akamai-Transformed', 'AkamaiGHost'],
                'cookies': ['akamai']
            },
            'Imperva': {
                'headers': ['X-Iinfo', 'X-Protected-By'],
                'cookies': ['visid_incap', 'incap_ses'],
                'body': ['incapsula'],
                'patterns': [r'incapsula.*incident']
            },
            'AWS WAF': {
                'headers': ['x-aws-waf-action', 'x-aws-waf-request-id'],
                'body': ['aws waf', 'request blocked']
            },
            'F5 BIG-IP': {
                'headers': ['X-Cnection', 'X-WA-Info'],
                'cookies': ['TS', 'F5_TrafficShield'],
                'body': ['F5-TrafficShield', 'BIG-IP'],
                'patterns': [r'bigip.*denied']
            },
            'Barracuda': {
                'headers': ['barra_counter_session'],
                'body': ['barra_counter_session', 'barracuda']
            },
            'Fortinet': {
                'headers': ['FORTIWAFSID'],
                'cookies': ['FORTIWAFSID'],
                'body': ['FortiWeb', 'FortiGuard'],
                'patterns': [r'forti.*blocked']
            },
            'Sucuri': {
                'headers': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
                'body': ['sucuri', 'access denied'],
                'patterns': [r'sucuri.*website firewall']
            }
        }

    def _carregar_payloads(self) -> List[str]:
        """Carrega payloads para teste de WAF"""
        return [
            "../../etc/passwd",
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "<?php system('id'); ?>",
            "${jndi:ldap://",
            "|cat /etc/passwd",
            "union select 1,2,3,4,5--",
            "<img src=x onerror=alert(1)>"
        ]

    def normalizar_url(self, url: str) -> str:
        """Normaliza a URL para requisição"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def detectar_waf(self, alvo: str) -> Dict:
        """Detecta WAFs usando assinaturas e payloads"""
        url = self.normalizar_url(alvo)
        resultados = {
            'waf_detectado': False,
            'tipo_waf': None,
            'evidencias': [],
            'payloads_bloqueados': []
        }

        # Testa payloads maliciosos
        resultados['payloads_bloqueados'] = self._testar_payloads(url)

        # Verifica assinaturas de WAF
        resposta = self._fazer_requisicao_segura(url)
        if resposta:
            resultados.update(self._verificar_assinaturas(resposta))

        # Determina se WAF foi detectado
        resultados['waf_detectado'] = resultados['tipo_waf'] is not None or len(resultados['payloads_bloqueados']) > 0

        return resultados

    def _fazer_requisicao_segura(self, url: str) -> Optional[requests.Response]:
        """Faz requisição HTTP segura com tratamento de erros"""
        try:
            return requests.get(
                url,
                headers={'User-Agent': self.user_agent},
                timeout=self.timeout,
                verify=False
            )
        except requests.exceptions.RequestException:
            return None

    def _testar_payloads(self, url: str) -> List[Dict]:
        """Testa payloads maliciosos para detecção de WAF"""
        bloqueios = []
        for payload in self.payloads:
            try:
                resposta = requests.get(
                    url,
                    params={'test': payload},
                    headers={'User-Agent': self.user_agent},
                    timeout=self.timeout,
                    verify=False
                )
                
                if resposta.status_code in [403, 406, 429, 503, 418]:
                    bloqueios.append({
                        'payload': payload,
                        'status': resposta.status_code,
                        'detalhes': self._analisar_resposta_bloqueio(resposta)
                    })
            except requests.exceptions.RequestException:
                continue
        return bloqueios

    def _analisar_resposta_bloqueio(self, resposta: requests.Response) -> Dict:
        """Analisa padrões na resposta de bloqueio"""
        detalhes = {
            'status_code': resposta.status_code,
            'headers': dict(resposta.headers)
        }

        for waf, assinaturas in self.assinaturas_waf.items():
            for pattern in assinaturas.get('patterns', []):
                if re.search(pattern, resposta.text, re.IGNORECASE):
                    detalhes['padrao_waf'] = f"{waf}: {pattern}"
                    break

        return detalhes

    def _verificar_assinaturas(self, resposta: requests.Response) -> Dict:
        """Verifica assinaturas de WAF na resposta"""
        resultados = {
            'tipo_waf': None,
            'evidencias': []
        }

        for waf, assinaturas in self.assinaturas_waf.items():
            # Verifica headers
            for header, value in resposta.headers.items():
                for pattern in assinaturas.get('headers', []):
                    if re.search(pattern, header, re.IGNORECASE) or re.search(pattern, value, re.IGNORECASE):
                        resultados['evidencias'].append(f"Header match: {header}:{value} ({waf})")
                        resultados['tipo_waf'] = waf

            # Verifica cookies
            for cookie in resposta.cookies:
                for pattern in assinaturas.get('cookies', []):
                    if re.search(pattern, cookie.name, re.IGNORECASE):
                        resultados['evidencias'].append(f"Cookie match: {cookie.name} ({waf})")
                        resultados['tipo_waf'] = waf

            # Verifica corpo da resposta
            for pattern in assinaturas.get('patterns', []):
                if re.search(pattern, resposta.text, re.IGNORECASE):
                    resultados['evidencias'].append(f"Body pattern match: {pattern} ({waf})")
                    resultados['tipo_waf'] = waf

        return resultados


# Exemplo de uso
if __name__ == "__main__":
    detector = DetectorWAF()
    resultado = detector.detectar_waf("https://exemplo.com")
    
    print("\nResultados da Detecção WAF:")
    print(f"WAF Detectado: {'Sim' if resultado['waf_detectado'] else 'Não'}")
    if resultado['tipo_waf']:
        print(f"Tipo de WAF: {resultado['tipo_waf']}")
    
    if resultado['evidencias']:
        print("\nEvidências encontradas:")
        for evidencia in resultado['evidencias']:
            print(f"- {evidencia}")
    
    if resultado['payloads_bloqueados']:
        print(f"\nPayloads bloqueados ({len(resultado['payloads_bloqueados'])}):")
        for bloqueio in resultado['payloads_bloqueados']:
            print(f"- {bloqueio['payload']} (Status: {bloqueio['status']})")