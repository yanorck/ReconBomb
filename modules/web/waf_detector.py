import requests
from config.settings import USER_AGENT, WEB_TIMEOUT, WAF_TEST_PAYLOADS
import urllib3

# Desativa avisos de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DetectorWAF:
    def __init__(self):
        self.assinaturas_waf = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status'],
                'cookies': ['__cfduid', 'cf_clearance'],
                'body': ['cloudflare-nginx', 'cloudflare']
            },
            'ModSecurity': {
                'headers': ['mod_security', 'NOYB'],
                'body': ['ModSecurity', 'Mod_Security', 'NOYB']
            },
            'Akamai': {
                'headers': ['X-Akamai-Transformed'],
                'cookies': ['akamai']
            },
            'Imperva': {
                'headers': ['X-Iinfo'],
                'cookies': ['visid_incap', 'incap_ses'],
                'body': ['incapsula']
            },
            'F5 BIG-IP': {
                'headers': ['X-Cnection', 'X-WA-Info'],
                'cookies': ['TS', 'F5_TrafficShield'],
                'body': ['F5-TrafficShield']
            },
            'Barracuda': {
                'headers': ['barra_counter_session'],
                'body': ['barra_counter_session']
            },
            'Fortinet': {
                'headers': ['FORTIWAFSID'],
                'cookies': ['FORTIWAFSID'],
                'body': ['FortiWeb']
            }
        }

    def normalizar_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def detectar_waf(self, alvo):
        url = self.normalizar_url(alvo)
        resultados = {
            'waf_detectado': False,
            'tipo_waf': None,
            'evidencias': [],
            'payloads_bloqueados': []
        }

        # Testa payloads maliciosos
        for payload in WAF_TEST_PAYLOADS:
            try:
                resposta = requests.get(
                    url,
                    params={'q': payload},
                    headers={'User-Agent': USER_AGENT},
                    timeout=WEB_TIMEOUT,
                    verify=False
                )
                
                # Verifica se o payload foi bloqueado
                if resposta.status_code in [403, 406, 429, 503]:
                    resultados['payloads_bloqueados'].append({
                        'payload': payload,
                        'status': resposta.status_code
                    })
            except requests.exceptions.RequestException:
                continue

        # Verifica assinaturas de WAF
        try:
            resposta = requests.get(
                url,
                headers={'User-Agent': USER_AGENT},
                timeout=WEB_TIMEOUT,
                verify=False
            )

            # Verifica headers
            for nome_waf, assinaturas in self.assinaturas_waf.items():
                # Verifica headers
                for header in assinaturas.get('headers', []):
                    if header.lower() in [h.lower() for h in resposta.headers]:
                        resultados['waf_detectado'] = True
                        resultados['tipo_waf'] = nome_waf
                        resultados['evidencias'].append(f"Header encontrado: {header}")
                        break

                # Verifica cookies
                for cookie in assinaturas.get('cookies', []):
                    if cookie.lower() in [c.lower() for c in resposta.cookies]:
                        resultados['waf_detectado'] = True
                        resultados['tipo_waf'] = nome_waf
                        resultados['evidencias'].append(f"Cookie encontrado: {cookie}")
                        break

                # Verifica corpo da resposta
                for padrao in assinaturas.get('body', []):
                    if padrao.lower() in resposta.text.lower():
                        resultados['waf_detectado'] = True
                        resultados['tipo_waf'] = nome_waf
                        resultados['evidencias'].append(f"Padrão encontrado no corpo: {padrao}")
                        break

        except requests.exceptions.RequestException as e:
            resultados['erro'] = str(e)

        return resultados 