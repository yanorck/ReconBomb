import logging
import os
from datetime import datetime
from config.settings import LOG_LEVEL, LOG_FILE, LOG_FORMAT

class Logger:
    def __init__(self, name='ReconBomb'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, LOG_LEVEL))
        
        # Cria o diretório de logs se não existir
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Configura o handler do arquivo
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        self.logger.addHandler(file_handler)
        
        # Configura o handler do console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        self.logger.addHandler(console_handler)
    
    def debug(self, message):
        self.logger.debug(message)
    
    def info(self, message):
        self.logger.info(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def critical(self, message):
        self.logger.critical(message)
    
    def log_scan_start(self, target):
        self.info(f"Iniciando scan do alvo: {target}")
    
    def log_scan_end(self, target):
        self.info(f"Scan do alvo {target} finalizado")
    
    def log_module_start(self, module_name, target):
        self.info(f"Iniciando módulo {module_name} no alvo {target}")
    
    def log_module_end(self, module_name, target):
        self.info(f"Módulo {module_name} finalizado no alvo {target}")
    
    def log_error(self, error, context=None):
        if context:
            self.error(f"Erro em {context}: {str(error)}")
        else:
            self.error(str(error))
    
    def log_warning(self, warning, context=None):
        if context:
            self.warning(f"Aviso em {context}: {str(warning)}")
        else:
            self.warning(str(warning))
    
    def log_result(self, result_type, target, details):
        self.info(f"Resultado {result_type} para {target}: {details}")
    
    def log_config_change(self, setting, old_value, new_value):
        self.info(f"Configuração alterada: {setting} de {old_value} para {new_value}")
    
    def log_security_event(self, event_type, target, details):
        self.warning(f"Evento de segurança {event_type} detectado em {target}: {details}")
    
    def log_performance(self, operation, duration):
        self.debug(f"Operação {operation} levou {duration:.2f} segundos")
    
    def log_connection(self, protocol, target, port, status):
        self.debug(f"Conexão {protocol} para {target}:{port} - Status: {status}")
    
    def log_dns_query(self, query_type, domain, result):
        self.debug(f"Consulta DNS {query_type} para {domain}: {result}")
    
    def log_web_request(self, method, url, status_code):
        self.debug(f"Requisição {method} para {url} - Status: {status_code}")
    
    def log_ssl_info(self, hostname, cert_info):
        self.info(f"Informações SSL/TLS para {hostname}: {cert_info}")
    
    def log_waf_detection(self, target, waf_type, evidence):
        self.info(f"WAF {waf_type} detectado em {target}: {evidence}")
    
    def log_technology_detection(self, target, tech, version=None):
        if version:
            self.info(f"Tecnologia {tech} versão {version} detectada em {target}")
        else:
            self.info(f"Tecnologia {tech} detectada em {target}")
    
    def log_subdomain_discovery(self, domain, subdomain, ip):
        self.info(f"Subdomínio {subdomain}.{domain} encontrado - IP: {ip}")
    
    def log_vulnerability(self, target, vuln_type, details):
        self.warning(f"Vulnerabilidade {vuln_type} encontrada em {target}: {details}")
    
    def log_scan_progress(self, target, progress, total):
        percentage = (progress / total) * 100
        self.info(f"Progresso do scan em {target}: {percentage:.1f}% ({progress}/{total})") 