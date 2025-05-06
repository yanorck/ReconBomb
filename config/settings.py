# Configurações gerais
TIMEOUT = 10
MAX_THREADS = 100
VERIFY_SSL = False

# Configurações de rede
DEFAULT_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
COMMON_WEB_PORTS = [80, 443, 8080, 8443, 3000, 8000, 8008, 8888]

# Configurações de reconhecimento web
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
WEB_TIMEOUT = 10

# Configurações de DNS
DNS_SERVERS = [
    '8.8.8.8',  # Google
    '8.8.4.4',  # Google
    '1.1.1.1',  # Cloudflare
    '1.0.0.1'   # Cloudflare
]

# Configurações de subdomínios
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'admin', 'blog',
    'dev', 'test', 'stage', 'api', 'cdn', 'cloud', 'shop',
    'store', 'support', 'help', 'portal', 'intranet', 'vpn'
]

# Configurações de WAF
WAF_TEST_PAYLOADS = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "UNION SELECT",
    "exec xp_cmdshell"
]

# Configurações de saída
OUTPUT_FORMAT = 'table'  # 'table', 'json', 'csv'
SAVE_RESULTS = True
OUTPUT_DIR = 'results'

# Configurações de logging
LOG_LEVEL = 'INFO'
LOG_FILE = 'reconbomb.log'
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

# Configurações de cores
COLORS = {
    'SUCCESS': 'green',
    'ERROR': 'red',
    'WARNING': 'yellow',
    'INFO': 'blue',
    'HEADER': 'magenta'
} 