# ReconBomb - Ferramenta de Reconhecimento de Segurança

Ferramenta modular para reconhecimento em testes de penetração.

## Funcionalidades

- PortScan (TCP/UDP)
- WHOIS Lookup
- DNS Enumeration
- Subdomain Scanner
- SSL/TLS Analysis
- Web Technology Detection
- Directory Enumeration
- WAF Detection

## Requisitos

- Python 3.8+
- Dependências listadas em requirements.txt

## Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/ReconBomb.git
cd ReconBomb
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## Uso

Execute o programa principal:
```bash
python main.py
```

## Estrutura do Projeto

```
ReconBomb/
├── main.py                 # Ponto de entrada do programa
├── requirements.txt        # Dependências do projeto
├── modules/               # Módulos de reconhecimento
│   ├── port_scan/        # Módulo de escaneamento de portas
│   ├── dns/              # Módulo de enumeração DNS
│   ├── web/              # Módulos de reconhecimento web
│   └── network/          # Módulos de reconhecimento de rede
├── utils/                # Utilitários comuns
│   ├── cli.py           # Interface de linha de comando
│   └── output.py        # Formatação de saída
└── config/              # Arquivos de configuração
```

## Contribuindo

Contribuições são bem-vindas! Por favor, leia as diretrizes de contribuição antes de enviar um pull request.

## Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para detalhes.