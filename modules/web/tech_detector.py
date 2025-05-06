import requests
from bs4 import BeautifulSoup
from typing import Dict, List
import re
from urllib.parse import urlparse

class DetectorTecnologias:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.tecnologias = {
            'cms': {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                'joomla': ['joomla', 'com_content'],
                'drupal': ['drupal', 'sites/all'],
                'magento': ['magento', 'skin/frontend']
            },
            'frameworks': {
                'laravel': ['laravel', 'csrf-token'],
                'django': ['csrfmiddlewaretoken', 'django'],
                'rails': ['rails', 'csrf-token'],
                'angular': ['ng-app', 'ng-controller'],
                'react': ['react', 'react-dom'],
                'vue': ['vue', 'v-bind']
            },
            'servidores': {
                'apache': ['apache', 'mod_'],
                'nginx': ['nginx'],
                'iis': ['iis', 'asp.net'],
                'tomcat': ['tomcat', 'jsp']
            },
            'linguagens': {
                'php': ['php', '.php'],
                'python': ['python', '.py'],
                'ruby': ['ruby', '.rb'],
                'java': ['java', '.jsp'],
                'asp': ['asp', '.asp'],
                'node': ['node', 'express']
            }
        }

    def normalizar_url(self, url: str) -> str:
        """Normaliza a URL para garantir que tenha o protocolo correto."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url

    def detectar_tecnologias(self, url):
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            resposta = requests.get(url, headers=self.headers, verify=False, timeout=10)
            conteudo = resposta.text
            soup = BeautifulSoup(conteudo, 'html.parser')
            
            resultados = {
                'cms': [],
                'frameworks': [],
                'servidores': [],
                'linguagens': []
            }
            
            for categoria, tecs in self.tecnologias.items():
                for tec, padroes in tecs.items():
                    for padrao in padroes:
                        if padrao.lower() in conteudo.lower():
                            if tec not in resultados[categoria]:
                                resultados[categoria].append(tec)
            
            headers = resposta.headers
            if 'server' in headers:
                servidor = headers['server'].lower()
                for tec, padroes in self.tecnologias['servidores'].items():
                    if any(padrao in servidor for padrao in padroes):
                        if tec not in resultados['servidores']:
                            resultados['servidores'].append(tec)
            
            return resultados
            
        except Exception as e:
            return {'erro': str(e)}

    def obter_headers(self, url: str) -> Dict[str, str]:
        """
        Obtém os headers HTTP do site.
        
        Args:
            url: URL do site alvo
            
        Returns:
            Dicionário com os headers
        """
        url = self.normalizar_url(url)
        try:
            response = requests.head(url, headers=self.headers, timeout=10, verify=False)
            return dict(response.headers)
        except requests.exceptions.RequestException as e:
            return {'Erro': str(e)} 