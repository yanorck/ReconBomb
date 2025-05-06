import json
import csv
import os
from datetime import datetime
from typing import Dict, List, Any
from config.settings import OUTPUT_FORMAT, SAVE_RESULTS, OUTPUT_DIR

class OutputManager:
    def __init__(self):
        self.output_dir = OUTPUT_DIR
        if SAVE_RESULTS and not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def _get_timestamp(self) -> str:
        """Retorna o timestamp atual formatado."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _get_output_filename(self, target: str, scan_type: str) -> str:
        """Gera um nome de arquivo para os resultados."""
        timestamp = self._get_timestamp()
        return os.path.join(self.output_dir, f"{target}_{scan_type}_{timestamp}")
    
    def save_results(self, target: str, scan_type: str, results: Dict[str, Any]) -> str:
        """
        Salva os resultados em um arquivo.
        
        Args:
            target: Alvo do scan
            scan_type: Tipo de scan realizado
            results: Resultados a serem salvos
            
        Returns:
            Caminho do arquivo salvo
        """
        if not SAVE_RESULTS:
            return None
        
        filename = self._get_output_filename(target, scan_type)
        
        if OUTPUT_FORMAT == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
        
        elif OUTPUT_FORMAT == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                for key, value in results.items():
                    if isinstance(value, list):
                        writer.writerow([key] + value)
                    else:
                        writer.writerow([key, value])
        
        return filename
    
    def format_results(self, results: Dict[str, Any], format_type: str = None) -> str:
        """
        Formata os resultados para exibição.
        
        Args:
            results: Resultados a serem formatados
            format_type: Tipo de formatação desejada
            
        Returns:
            String formatada com os resultados
        """
        format_type = format_type or OUTPUT_FORMAT
        
        if format_type == 'json':
            return json.dumps(results, indent=4)
        
        elif format_type == 'csv':
            output = []
            for key, value in results.items():
                if isinstance(value, list):
                    output.append(f"{key},{','.join(str(v) for v in value)}")
                else:
                    output.append(f"{key},{value}")
            return '\n'.join(output)
        
        else:  # table
            output = []
            max_key_length = max(len(str(k)) for k in results.keys())
            for key, value in results.items():
                if isinstance(value, list):
                    value_str = '\n'.join(f"  {v}" for v in value)
                    output.append(f"{str(key):<{max_key_length}} :\n{value_str}")
                else:
                    output.append(f"{str(key):<{max_key_length}} : {value}")
            return '\n'.join(output)
    
    def save_scan_summary(self, target: str, scan_results: Dict[str, Any]) -> str:
        """
        Salva um resumo do scan.
        
        Args:
            target: Alvo do scan
            scan_results: Resultados do scan
            
        Returns:
            Caminho do arquivo salvo
        """
        if not SAVE_RESULTS:
            return None
        
        summary = {
            'target': target,
            'timestamp': self._get_timestamp(),
            'scan_types': list(scan_results.keys()),
            'findings': {
                scan_type: len(results) for scan_type, results in scan_results.items()
            }
        }
        
        filename = self._get_output_filename(target, 'summary')
        if OUTPUT_FORMAT == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump(summary, f, indent=4)
        
        return filename
    
    def save_vulnerability_report(self, target: str, vulnerabilities: List[Dict[str, Any]]) -> str:
        """
        Salva um relatório de vulnerabilidades.
        
        Args:
            target: Alvo do scan
            vulnerabilities: Lista de vulnerabilidades encontradas
            
        Returns:
            Caminho do arquivo salvo
        """
        if not SAVE_RESULTS:
            return None
        
        filename = self._get_output_filename(target, 'vulnerabilities')
        
        if OUTPUT_FORMAT == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump(vulnerabilities, f, indent=4)
        
        elif OUTPUT_FORMAT == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=vulnerabilities[0].keys())
                writer.writeheader()
                writer.writerows(vulnerabilities)
        
        return filename
    
    def save_technology_report(self, target: str, technologies: Dict[str, List[str]]) -> str:
        """
        Salva um relatório de tecnologias detectadas.
        
        Args:
            target: Alvo do scan
            technologies: Dicionário com tecnologias detectadas
            
        Returns:
            Caminho do arquivo salvo
        """
        if not SAVE_RESULTS:
            return None
        
        filename = self._get_output_filename(target, 'technologies')
        
        if OUTPUT_FORMAT == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump(technologies, f, indent=4)
        
        elif OUTPUT_FORMAT == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                for tech, versions in technologies.items():
                    writer.writerow([tech] + versions)
        
        return filename
    
    def save_dns_report(self, target: str, dns_records: Dict[str, List[str]]) -> str:
        """
        Salva um relatório de registros DNS.
        
        Args:
            target: Alvo do scan
            dns_records: Dicionário com registros DNS
            
        Returns:
            Caminho do arquivo salvo
        """
        if not SAVE_RESULTS:
            return None
        
        filename = self._get_output_filename(target, 'dns')
        
        if OUTPUT_FORMAT == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump(dns_records, f, indent=4)
        
        elif OUTPUT_FORMAT == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                for record_type, records in dns_records.items():
                    writer.writerow([record_type] + records)
        
        return filename 