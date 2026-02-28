# 🔐 API Security Scanner

Scanner de segurança automatizado para APIs REST, desenvolvido em Python com arquitetura limpa e modular.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

---

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Funcionalidades](#-funcionalidades)
- [Arquitetura](#-arquitetura)
- [Instalação](#-instalação)
- [Uso](#-uso)
- [Módulos de Segurança](#-módulos-de-segurança)
- [Sistema de Pontuação](#-sistema-de-pontuação)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Exemplos](#-exemplos)
- [Desenvolvimento](#-desenvolvimento)

---

## 🎯 Visão Geral

O **API Security Scanner** é uma ferramenta de linha de comando que analisa APIs REST em busca de vulnerabilidades de segurança comuns, seguindo as melhores práticas da OWASP.

### Características Principais:

- ✅ **Execução paralela** de módulos de teste
- ✅ **Sistema de pontuação** (0-100) baseado em severidade
- ✅ **Relatórios em JSON** e texto
- ✅ **Arquitetura modular** - fácil adicionar novos testes
- ✅ **Clean Architecture** - separação clara de responsabilidades
- ✅ **Zero configuração** - funciona out-of-the-box

---

## ⚡ Funcionalidades

### Verificações de Segurança

| Categoria | Verificações |
|-----------|--------------|
| **Headers** | 7 security headers críticos (HSTS, CSP, X-Frame-Options, etc) |
| **CORS** | Misconfigurações, wildcard origins, reflection attacks |
| **Rate Limiting** | Ausência de proteção contra brute force |
| **Authentication** | Endpoints sem autenticação, bypass de controle de acesso |

### Recursos

- 🔍 **Scan completo** em segundos
- 📊 **Score de segurança** de 0 a 100
- 🎨 **Output colorido** no terminal
- 💾 **Exportação JSON** para integração
- ⏱️ **Timeouts configuráveis** (global e por módulo)
- 🔄 **Retry automático** em falhas temporárias
- 📝 **Logs detalhados** em arquivo

---

## 🏗️ Arquitetura

O projeto segue **Clean Architecture** com separação em camadas:

```
┌─────────────────────────────────────────┐
│          Interface (CLI)                │  ← Entrada do usuário
├─────────────────────────────────────────┤
│      Application (Engine, Loader)       │  ← Orquestração
├─────────────────────────────────────────┤
│   Infrastructure (HTTP, Logging)        │  ← Implementações técnicas
├─────────────────────────────────────────┤
│     Domain (Entities, Rules)            │  ← Regras de negócio puras
└─────────────────────────────────────────┘
```

### Camadas:

- **Domain**: Entidades puras (`Target`, `Vulnerability`, `Scan`, `ScanResult`)
- **Application**: Engine de scan, carregador de módulos, contratos
- **Infrastructure**: Cliente HTTP (`requests`), sistema de logs
- **Interface**: CLI com `argparse`

---

## 🚀 Instalação

> 💡 **Em breve:** Instalação via pip estará disponível!

### Pré-requisitos

- Python 3.10 ou superior
- pip (gerenciador de pacotes)

### Passo a Passo

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/api-security-scanner.git
cd api-security-scanner

# 2. Crie ambiente virtual
python -m venv .venv

# 3. Ative o ambiente virtual
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux/Mac
source .venv/bin/activate

# 4. Instale dependências
pip install -r requirements.txt
```

### Dependências

```txt
requests>=2.31.0
urllib3>=2.0.0
```

---

## 💻 Uso

### Comandos Disponíveis

#### 1. Executar Scan

```bash
python main.py scan <URL>
```

**Exemplo:**
```bash
python main.py scan https://api.exemplo.com
```

#### 2. Listar Módulos

```bash
python main.py list-modules
```

#### 3. Ajuda

```bash
python main.py --help
python main.py scan --help
```

### Opções do Scan

| Opção | Descrição | Padrão |
|-------|-----------|--------|
| `--timeout` | Timeout global em segundos | 300 |
| `--module-timeout` | Timeout por módulo em segundos | 30 |
| `--output` | Arquivo de saída (JSON/TXT). Para JSON a saída não pode sobrescrever um arquivo existente; escolha um nome único. | - |
| `--no-color` | Desabilitar cores no terminal | False |
| `--verbose` | Logs detalhados | False |

### Exemplos de Uso

**Scan básico:**
```bash
python main.py scan https://httpbin.org
```

**Scan com timeout customizado:**
```bash
python main.py scan https://api.exemplo.com --timeout 600 --module-timeout 60
```

**Scan com saída JSON (arquivo deve ser exclusivo no diretório):**
```bash
python main.py scan https://api.exemplo.com --output resultado.json
```

**Scan sem cores (para CI/CD):**
```bash
python main.py scan https://api.exemplo.com --no-color
```

---

## 🔒 Módulos de Segurança

### 1. Headers Module

Verifica presença de **7 security headers** essenciais:

| Header | Severidade | Descrição |
|--------|-----------|-----------|
| `Strict-Transport-Security` | HIGH | Força uso de HTTPS |
| `Content-Security-Policy` | HIGH | Previne XSS e injection |
| `X-Frame-Options` | MEDIUM | Protege contra clickjacking |
| `X-Content-Type-Options` | MEDIUM | Previne MIME sniffing |
| `X-XSS-Protection` | LOW | Proteção XSS legada |
| `Referrer-Policy` | LOW | Controla informação de referrer |
| `Permissions-Policy` | LOW | Controla features do browser |

**Referência:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

### 2. CORS Module

Detecta **misconfigurações de CORS**:

- ❌ **Wildcard origin** (`Access-Control-Allow-Origin: *`) → CRITICAL
- ❌ **Credentials + Wildcard** → CRITICAL
- ❌ **Reflection attack** (aceita qualquer origem) → HIGH
- ❌ **Métodos perigosos** (PUT, DELETE, TRACE) → MEDIUM

**Referência:** [OWASP CORS](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)

### 3. Rate Limit Module

Testa **proteção contra brute force**:

- Envia 20 requisições sequenciais
- Detecta ausência de rate limiting → MEDIUM
- Verifica headers: `X-RateLimit-*`, `Retry-After`
- Detecta status code `429 Too Many Requests`

**Referência:** [OWASP Blocking Brute Force](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)

### 4. Authentication Module

Detecta **falhas de autenticação e controle de acesso**:

#### Endpoints Testados:
- **7 CRITICAL**: `/admin`, `/api/admin`, `/api/admin/users`, `/api/config`, `/api/settings`, `/console`, `/api/internal`
- **7 HIGH**: `/api/users`, `/api/customers`, `/api/orders`, `/api/payments`, `/api/transactions`, `/api/dashboard`, `/api/reports`
- **5 MEDIUM**: `/api/profile`, `/api/account`, `/api/me`, `/api/user`, `/api/data`
- **6 LOW**: `/api/status`, `/api/health`, `/api/metrics`, `/api/logs`, `/api/debug`

#### Testes Realizados:
- ❌ **Sem autenticação** → Endpoint retorna 200 sem Authorization header
- ❌ **Token vazio** → `Authorization: Bearer ` aceito
- ❌ **Token inválido** → `Authorization: Bearer invalid_token` aceito
- ❌ **Token malformado** → Token com formato incorreto aceito

#### Métodos HTTP testados:
- GET, POST, PUT, DELETE

#### Características:
- ✅ **Execução paralela** (5 workers simultâneos)
- ✅ **Smart skip** (se GET retorna 404, pula outros métodos)
- ✅ **Detecção REST API** (ignora HTML, aceita apenas JSON/XML)
- ✅ **Delay de 0.3s** entre requisições (respeitoso)
- ✅ **Timeout de 3s** por requisição

**Referência:** [OWASP Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)

---

## 📊 Sistema de Pontuação

### Cálculo do Score

O score inicia em **100 pontos** e é penalizado por severidade:

| Severidade | Penalidade | Cor |
|------------|-----------|-----|
| CRITICAL | -25 pontos | 🔴 Vermelho |
| HIGH | -15 pontos | 🟠 Laranja |
| MEDIUM | -10 pontos | 🟡 Amarelo |
| LOW | -5 pontos | 🟢 Verde |

**Score mínimo:** 0 pontos

### Níveis de Risco

| Score | Nível | Descrição |
|-------|-------|-----------|
| 90-100 | **A** | ✅ Seguro - Nenhum problema crítico |
| 75-89 | **B** | 🟦 Baixo Risco - Poucos problemas |
| 50-74 | **C** | 🟨 Risco Moderado - Atenção necessária |
| 0-49 | **D** | 🟥 Alto Risco - Ação imediata recomendada |

### Exemplo de Cálculo

```
Vulnerabilidades encontradas:
- 2 HIGH   (2 × 15 = -30)
- 3 MEDIUM (3 × 10 = -30)
- 1 LOW    (1 × 5  = -5)

Score final: 100 - 30 - 30 - 5 = 35/100 (Nível D)
```

---

## 📁 Estrutura do Projeto

```
API_Scan/
├── .venv/                          # Ambiente virtual
├── logs/                           # Logs de execução
│   └── scan_YYYYMMDD_HHMMSS.log
├── src/
│   ├── domain/                     # Camada de Domínio
│   │   ├── __init__.py
│   │   ├── enums.py               # Severity, ScanStatus
│   │   ├── entities.py            # Target, Vulnerability, Scan
│   │   ├── value_objects.py       # ScanResult
│   │   └── exceptions.py          # Exceções customizadas
│   │
│   ├── application/                # Camada de Aplicação
│   │   ├── __init__.py
│   │   ├── contracts.py           # Protocols (interfaces)
│   │   ├── module_loader.py       # Carregador dinâmico
│   │   └── engine.py              # Engine de orquestração
│   │
│   ├── infrastructure/             # Camada de Infraestrutura
│   │   ├── __init__.py
│   │   ├── http_client.py         # Cliente HTTP (requests)
│   │   └── logger.py              # Sistema de logs
│   │
│   ├── interfaces/                 # Camada de Interface
│   │   ├── __init__.py
│   │   └── cli.py                 # Interface CLI
│   │
│   └── modules/                    # Módulos de Segurança
│       ├── __init__.py
│       ├── headers_module.py      # Verificação de headers
│       ├── cors_module.py         # Verificação CORS
│       ├── rate_limit_module.py   # Verificação rate limit
│       └── authentication_module.py # Verificação de autenticação
│
├── main.py                         # Ponto de entrada
├── requirements.txt                # Dependências
└── README.md                       # Este arquivo
```

---

## 📚 Exemplos

### Exemplo 1: Scan Simples

```bash
python main.py scan https://httpbin.org
```

**Output:**
```
╔═══════════════════════════════════════════════════════════════╗
║             🔐 API SECURITY SCANNER v1.0                      ║
╚═══════════════════════════════════════════════════════════════╝

🎯 Target: https://httpbin.org
🔒 Secure: Sim (HTTPS)

🔍 Iniciando scan em https://httpbin.org
📦 4 módulos ativos
⏱️  Timeout global: 300s

  🔴 headers_module: 8 vulnerabilidade(s)
  🔴 cors_module: 2 vulnerabilidade(s)
  🔴 rate_limit_module: 1 vulnerabilidade(s)
  🟢 authentication_module: 0 vulnerabilidade(s)

✅ Scan finalizado!
⏱️  Duração: 8.50s
🔍 Vulnerabilidades encontradas: 11

════════════════════════════════════════════════════════════════
📊 RESULTADO DO SCAN
════════════════════════════════════════════════════════════════

🎯 Target: https://httpbin.org
⏱️  Duração: 7.68s
📊 Score: 0/100
⚠️  Nível de Risco: D - Alto Risco - Ação imediata recomendada

────────────────────────────────────────────────────────────────
🔍 VULNERABILIDADES ENCONTRADAS
────────────────────────────────────────────────────────────────

Total: 11
  🟠 Altas: 4
  🟡 Médias: 4
  🟢 Baixas: 3
```

### Exemplo 2: Resultado JSON

```bash
python main.py scan https://httpbin.org --output resultado.json
```

**resultado.json:**
```json
{
  "target": {
    "url": "https://httpbin.org",
    "is_secure": true
  },
  "scan_id": "97477508-e983-44b5-a906-1a554d53a9bf",
  "summary": {
    "total_vulnerabilities": 11,
    "by_severity": {
      "critical": 0,
      "high": 4,
      "medium": 4,
      "low": 3
    },
    "score": 0,
    "risk_level": "D",
    "risk_description": "Alto Risco - Ação imediata recomendada"
  },
  "execution": {
    "duration_seconds": 6.396141,
    "duration_formatted": "6.40s"
  },
  "vulnerabilities": {
    "critical": [],
    "high": [
      {
        "id": "HEADERS-STRICT_TRANSPORT_SECURITY",
        "title": "Missing Security Header: Strict-Transport-Security",
        "severity": "high",
        "severity_label": "Alto",
        "module_name": "headers_module",
        "description": "Força uso de HTTPS",
        "evidence": "Header 'Strict-Transport-Security' não encontrado na resposta",
        "recommendation": "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "reference": "https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
        "timestamp": "2024-02-18T14:30:48.123456"
      },
      {
        "id": "HEADERS-CONTENT_SECURITY_POLICY",
        "title": "Missing Security Header: Content-Security-Policy",
        "severity": "high",
        "severity_label": "Alto",
        "module_name": "headers_module",
        "description": "Previne XSS e injection attacks",
        "evidence": "Header 'Content-Security-Policy' não encontrado na resposta",
        "recommendation": "Adicionar Content-Security-Policy com diretivas apropriadas",
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy",
        "timestamp": "2024-02-18T14:30:48.234567"
      }
    ],
    "medium": [
      {
        "id": "HEADERS-X_FRAME_OPTIONS",
        "title": "Missing Security Header: X-Frame-Options",
        "severity": "medium",
        "severity_label": "Médio",
        "module_name": "headers_module",
        "description": "Protege contra clickjacking",
        "evidence": "Header 'X-Frame-Options' não encontrado na resposta",
        "recommendation": "Adicionar: X-Frame-Options: DENY ou SAMEORIGIN",
        "reference": "https://owasp.org/www-community/attacks/Clickjacking",
        "timestamp": "2024-02-18T14:30:47.123456"
      }
    ],
    "low": [
      {
        "id": "HEADERS-X_XSS_PROTECTION",
        "title": "Missing Security Header: X-XSS-Protection",
        "severity": "low",
        "severity_label": "Baixo",
        "module_name": "headers_module",
        "description": "Ativa proteção XSS do browser",
        "evidence": "Header 'X-XSS-Protection' não encontrado na resposta",
        "recommendation": "Adicionar: X-XSS-Protection: 1; mode=block",
        "reference": "https://owasp.org/www-community/attacks/xss/",
        "timestamp": "2024-02-18T14:30:48.345678"
      }
    ]
  }
}
```

### Exemplo 3: Listar Módulos

```bash
python main.py list-modules
```

**Output:**
```
📦 Total de módulos: 4
✅ Ativos: 4
❌ Desabilitados: 0

────────────────────────────────────────────────────────────────
STATUS   NOME                      CATEGORIA       PRIORIDADE
────────────────────────────────────────────────────────────────
✓        headers_module            headers         0
         Verifica presença de security headers importantes

✓        cors_module               cors            1
         Verifica configuração de CORS e possíveis misconfigurações

✓        rate_limit_module         rate_limiting   2
         Verifica se a API possui rate limiting para prevenir brute force

✓        authentication_module     authentication  4
         Detecta falhas de autenticação e bypass de controle de acesso
```

---

## 🛠️ Desenvolvimento

### Adicionar Novo Módulo

1. Crie arquivo em `src/modules/nome_module.py`
2. Implemente o contrato `SecurityModuleProtocol`:

```python
from typing import List
from src.domain import Target, Vulnerability, Severity
from src.application.contracts import HttpClientProtocol


class MeuModule:
    name = "meu_module"
    description = "Descrição do módulo"
    category = "categoria"
    priority = 3
    enabled = True
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Sua lógica aqui
        
        return vulnerabilities
```

3. O módulo será carregado automaticamente! ✅

### Estrutura de Vulnerability

```python
Vulnerability(
    id="MODULE-IDENTIFIER",           # Ex: "SQL-INJECTION-001"
    title="Título da vulnerabilidade",
    severity=Severity.HIGH,            # CRITICAL, HIGH, MEDIUM, LOW
    module_name=self.name,
    description="Descrição técnica",   # Opcional
    evidence="Evidência encontrada",   # Opcional
    recommendation="Como corrigir",    # Opcional
    reference="https://owasp.org/..."  # Opcional
)
```

### Exit Codes

| Código | Significado |
|--------|-------------|
| `0` | Sucesso (score ≥ 50) |
| `1` | Falha (score < 50 ou erro) |

---

## 🎯 Roadmap

### Versão Atual (v1.0)

- [x] Headers security verification
- [x] CORS misconfiguration detection
- [x] Rate limiting checks
- [x] Authentication & access control testing
- [x] Parallel module execution
- [x] Detailed logging system
- [x] JSON/TXT export

### Versão Futura

- [ ] **Publicação no PyPI** (instalação via pip)
- [ ] JWT security module
- [ ] Testes unitários com pytest
- [ ] Módulos adicionais (SQL Injection, SSL/TLS, XSS)
- [ ] Relatórios HTML com gráficos
- [ ] Exportação para PDF
- [ ] API REST (FastAPI)
- [ ] Dashboard web
- [ ] Integração CI/CD (GitHub Actions)
- [ ] Docker image
- [ ] Configuração via YAML
- [ ] Modo comparação (diff entre scans)
- [ ] Banco de dados para histórico

---

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

---

## 👥 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch (`git checkout -b feature/NovaFuncionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/NovaFuncionalidade`)
5. Abra um Pull Request

---

## 📧 Contato

Para dúvidas ou sugestões, abra uma [issue](https://github.com/seu-usuario/api-security-scanner/issues).

---

## 🙏 Agradecimentos

- [OWASP](https://owasp.org/) - Referências de segurança
- [Requests](https://requests.readthedocs.io/) - Cliente HTTP
- Comunidade Python

---

**Desenvolvido com ❤️ e ☕**