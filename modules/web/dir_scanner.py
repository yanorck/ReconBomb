import requests
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from config.settings import USER_AGENT, WEB_TIMEOUT
import urllib3

# Desativa avisos de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class EscaneadorDiretorios:
    def __init__(self):
        self.diretorios_comuns = [
            "admin", "administrator", "backup", "bin", "config", "db", "debug",
            "dev", "docs", "download", "downloads", "files", "forum", "forums",
            "ftp", "home", "images", "img", "includes", "install", "js", "lib",
            "libs", "log", "logs", "media", "mysql", "new", "news", "old",
            "php", "phpmyadmin", "plugins", "private", "public", "scripts",
            "secure", "security", "server", "service", "services", "site",
            "sites", "sql", "src", "staff", "static", "stats", "status",
            "support", "sys", "system", "temp", "test", "tests", "tmp", "tools",
            "upload", "uploads", "user", "users", "util", "utils", "web",
            "webadmin", "webmail", "wordpress", "wp", "wp-admin", "wp-content",
            "wp-includes", "www", "wwwroot", "xml"
        ]
        
        self.arquivos_comuns = [
            "robots.txt", "sitemap.xml", ".htaccess", "web.config",
            "config.php", "config.inc.php", "config.xml", "config.json",
            "config.yml", "config.yaml", "config.ini", "config.txt",
            "README", "README.md", "README.txt", "CHANGELOG", "CHANGELOG.md",
            "CHANGELOG.txt", "LICENSE", "LICENSE.md", "LICENSE.txt",
            "backup.zip", "backup.tar.gz", "backup.sql", "backup.db",
            "database.sql", "database.db", "dump.sql", "dump.db",
            "error.log", "access.log", "debug.log", "phpinfo.php",
            "info.php", "test.php", "phpmyadmin", "admin.php",
            "login.php", "wp-login.php", "administrator", "admin",
            "server-status", "server-info"
        ]

    def normalizar_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def verificar_caminho(self, url_base, caminho):
        url = f"{url_base}/{caminho}"
        try:
            resposta = requests.get(
                url,
                headers={'User-Agent': USER_AGENT},
                timeout=WEB_TIMEOUT,
                verify=False,
                allow_redirects=False
            )
            
            if resposta.status_code == 200:
                return {
                    'caminho': caminho,
                    'status': resposta.status_code,
                    'tamanho': len(resposta.content),
                    'tipo': resposta.headers.get('Content-Type', 'Desconhecido')
                }
            elif resposta.status_code in [301, 302, 307, 308]:
                return {
                    'caminho': caminho,
                    'status': resposta.status_code,
                    'redirecionamento': resposta.headers.get('Location', 'Desconhecido')
                }
            elif resposta.status_code == 403:
                return {
                    'caminho': caminho,
                    'status': resposta.status_code,
                    'mensagem': 'Acesso Negado'
                }
        except requests.exceptions.RequestException:
            pass
        return None

    def escanear_diretorios(self, alvo, max_threads=10):
        url_base = self.normalizar_url(alvo)
        caminhos_encontrados = []
        
        # Combina diretórios e arquivos para escanear
        caminhos_para_escanear = self.diretorios_comuns + self.arquivos_comuns
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for caminho in caminhos_para_escanear:
                futures.append(executor.submit(self.verificar_caminho, url_base, caminho))
            
            for future in tqdm(futures, total=len(caminhos_para_escanear), desc="Escaneando diretórios"):
                resultado = future.result()
                if resultado:
                    caminhos_encontrados.append(resultado)
        
        return caminhos_encontrados 