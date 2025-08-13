# DesyncHunter - Agente Autônomo para HTTP Request Smuggling

## 🎯 Visão Geral do Projeto

**DesyncHunter** é um sistema de agentes autônomos baseado em IA para detecção, validação e exploração automatizada de vulnerabilidades de HTTP Request Smuggling, focado especificamente nas técnicas modernas apresentadas na pesquisa "HTTP/1.1 Must Die" de James Kettle.

O sistema utiliza a Claude API como backend de inteligência artificial, implementando uma arquitetura multi-agente com feedback loops e aprendizado contínuo para maximizar a eficácia em programas de bug bounty.

---

## 🏗️ Arquitetura do Sistema

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                     DESYNC HUNTER                          │
├─────────────────────────────────────────────────────────────┤
│  Orchestrator (Main Controller)                            │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │   Recon     │ │ Detection   │ │ Validation  │           │
│  │   Agent     │ │   Agent     │ │   Agent     │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐           │
│  │Exploitation │ │  Learning   │ │ Cost/Benefit│           │
│  │   Agent     │ │   Agent     │ │  Analyzer   │           │
│  └─────────────┘ └─────────────┘ └─────────────┘           │
├─────────────────────────────────────────────────────────────┤
│  Knowledge Base │ Evidence DB │ Pattern Recognition       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🤖 Agentes Especializados

### 1. **Reconnaissance Agent**
**Responsabilidade**: Mapeamento completo da infraestrutura HTTP

**Funcionalidades**:
- Identificação de servidores front-end/back-end
- Detecção de CDNs (Cloudflare, Akamai, Fastly, etc.)
- Fingerprinting de tecnologias (nginx, Apache, IIS)
- Análise de cabeçalhos reveladores
- Mapeamento de arquitetura de proxy/load balancer
- Detecção de WAFs e suas configurações

**Outputs**:
- Fingerprint completo da infraestrutura
- Risk assessment inicial
- Recomendações de testes específicos
- Pontos de entrada potenciais

### 2. **Detection Agent**
**Responsabilidade**: Detecção sistemática de discrepâncias de parser

**Técnicas Implementadas** (baseadas em "HTTP/1.1 Must Die"):
- **V-H/H-V Discrepancies**: Content-Length mascarado
- **Expect-based Desync**: Vanilla e obfuscated Expect headers
- **0.CL Desync Detection**: Implicit-zero content length
- **Early-response Gadget Discovery**: /con, /nul, redirects
- **Transfer-Encoding Variants**: Chunked encoding discrepancies
- **HTTP/2 Downgrading Issues**: H2.CL, H2.TE detection

**Adaptive Testing Strategy**:
```python
# Exemplo de estratégia adaptativa
def generate_adaptive_tests(target_fingerprint):
    if "cloudflare" in target_fingerprint.cdn:
        return cloudflare_specific_tests()
    elif "nginx" in target_fingerprint.backend:
        return nginx_optimized_tests()
    elif "iis" in target_fingerprint.backend:
        return iis_specific_tests()
    
    return generic_desync_tests()
```

### 3. **Validation Agent**
**Responsabilidade**: Eliminação rigorosa de falsos positivos

**Validação Multi-camada**:
1. **Technical Confirmation**: Reprodução consistente da discrepância
2. **Behavior Analysis**: Análise de patterns de resposta únicos
3. **Timing Validation**: Verificação de timeouts e race conditions
4. **Semantic Consistency**: Validação lógica do comportamento observado
5. **Infrastructure Compatibility**: Verificação de compatibilidade com stack detectada

**Métricas de Confiança**:
- Reproducibility Score (0-1)
- Technical Consistency (0-1)
- Exploitation Feasibility (0-1)
- Impact Potential (0-1)
- **Confidence Threshold**: 0.85 para prosseguir com exploitation

### 4. **Exploitation Agent**
**Responsabilidade**: Desenvolvimento de exploits funcionais

**Estratégias de Exploração**:
- **CL.0 Desync**: Para V-H discrepancies
- **0.CL Desync**: Para H-V discrepancies com early-response gadgets
- **Double-Desync**: Conversão 0.CL → CL.0
- **Response Queue Poisoning (RQP)**: Para high-impact attacks
- **Cache Poisoning**: Persistent takeover via cache contamination
- **Header Smuggling**: IP spoofing e authentication bypass

**Exploit Development Pipeline**:
1. Identificar gadgets específicos do target
2. Calcular payloads baseado na infraestrutura
3. Implementar bypass de WAF quando necessário
4. Desenvolver PoC completo
5. Validar impacto real

### 5. **Learning Agent**
**Responsabilidade**: Aprendizado contínuo e otimização

**Capacidades de Aprendizado**:
- Pattern recognition de infraestruturas vulneráveis
- Otimização de thresholds baseado em resultados
- Geração de novos testes baseado em falhas
- Database de fingerprints bem-sucedidos
- Análise de tendências em bug bounty programs

### 6. **Cost/Benefit Analyzer**
**Responsabilidade**: Otimização econômica das operações

**Análises Realizadas**:
- Custo por token da Claude API
- ROI esperado por target
- Priorização baseada em recompensas históricas
- Budget allocation otimizado
- Stop-loss para targets não promissores

---

## 🔄 Fluxo de Operação

### Fase 1: Input Processing
```
Input: URL ou lista de URLs
↓
Validação e sanitização
↓
Priorização baseada em inteligência histórica
```

### Fase 2: Reconnaissance Paralelo
```
Para cada URL:
├── Fingerprinting de infraestrutura
├── Detecção de tecnologias
├── Análise de cabeçalhos
├── Risk assessment inicial
└── Geração de estratégia de teste
```

### Fase 3: Detection Inteligente
```
Para targets promissores:
├── Testes adaptativos baseados em fingerprint
├── Detecção de discrepâncias de parser
├── Descoberta de early-response gadgets
└── Coleta de evidências técnicas
```

### Fase 4: Validation Rigorosa
```
Para cada finding:
├── Confirmação técnica multi-camada
├── Análise de reprodutibilidade
├── Cálculo de confidence score
└── Decision gate (prosseguir ou não)
```

### Fase 5: Exploitation Focada
```
Para findings validados:
├── Desenvolvimento de exploit específico
├── Bypass de mitigações
├── Validação de impacto real
└── Geração de PoC para report
```

### Fase 6: Learning & Optimization
```
Após cada execução:
├── Atualização de knowledge base
├── Otimização de patterns
├── Ajuste de thresholds
└── Preparação para próximas execuções
```

---

## 📊 Sistema de Métricas e KPIs

### Métricas de Performance
- **Detection Rate**: % de vulnerabilidades reais detectadas
- **False Positive Rate**: < 5% (target)
- **Time to Detection**: Média de tempo para primeira detecção
- **Time to Exploit**: Tempo da detecção ao PoC funcional
- **Cost per Valid Finding**: Custo médio por vulnerabilidade validada

### Métricas de Business
- **ROI per Target**: Retorno sobre investimento por target analisado
- **Bounty Success Rate**: % de reports que resultaram em bounty
- **Average Bounty Value**: Valor médio de bounties recebidos
- **Cost Efficiency**: Custo total vs. bounties totais

### Métricas de Learning
- **Pattern Recognition Accuracy**: Precisão na identificação de patterns
- **Adaptation Speed**: Velocidade de adaptação a novos targets
- **Knowledge Retention**: Eficácia da knowledge base

---

## 🛠️ Implementação Técnica

### Stack Tecnológico
- **Backend**: Python 3.9+
- **AI Engine**: Anthropic Claude API (Sonnet 4)
- **HTTP Client**: aiohttp para requests assíncronos
- **Database**: SQLite para knowledge base local
- **Testing**: pytest para unit tests
- **Logging**: estruturado com contexto completo

### Estrutura de Diretórios
```
desync_hunter/
├── agents/
│   ├── reconnaissance.py
│   ├── detection.py
│   ├── validation.py
│   ├── exploitation.py
│   └── learning.py
├── core/
│   ├── orchestrator.py
│   ├── decision_engine.py
│   └── cost_analyzer.py
├── knowledge/
│   ├── patterns_db.py
│   ├── fingerprints.py
│   └── exploits_library.py
├── utils/
│   ├── http_client.py
│   ├── claude_interface.py
│   └── validators.py
├── tests/
├── config/
└── reports/
```

### Configuração e Customização
```yaml
# config.yaml
api:
  claude_api_key: "sk-ant-..."
  max_tokens_per_request: 1000
  cost_per_token: 0.000003

thresholds:
  confidence_minimum: 0.85
  max_cost_per_target: 10.00
  false_positive_tolerance: 0.05

targets:
  concurrent_analysis: 5
  timeout_per_target: 300
  retry_attempts: 3

learning:
  pattern_retention_days: 365
  minimum_evidence_samples: 10
  confidence_decay_rate: 0.1
```

---

## 🎯 Técnicas Específicas Implementadas

### Baseadas em "HTTP/1.1 Must Die"

#### 1. **V-H/H-V Discrepancy Detection**
```
Tests implementados:
├── Content-Length com espaços: " Content-Length: 23"
├── Content-Length com \n: "Content-Length:\n23"
├── Host header mascarado: " Host: target.com"
├── Duplicate headers com valores inválidos
└── Header case sensitivity tests
```

#### 2. **Expect-based Desync**
```
Variants testados:
├── Vanilla: "Expect: 100-continue"
├── Obfuscated: "Expect: y 100-continue"
├── Spaced: "Expect:\n100-continue"
├── Leading space: " Expect: 100-continue"
└── Invalid values: "Expect: 200-continue"
```

#### 3. **0.CL Desync com Early-Response Gadgets**
```
Gadgets testados:
├── Windows reserved names: /con, /nul, /aux, /prn
├── Server redirects: 301/302 responses
├── Static file optimizations: nginx early responses
├── Error conditions: 400/404 early responses
└── Authentication endpoints: 401/403 early responses
```

#### 4. **Double-Desync (0.CL → CL.0)**
```
Implementation strategy:
├── Primeira request: estabelece 0.CL desync
├── Segunda request: weaponiza conexão com CL.0
├── Payload injection: via header smuggling
├── Victim request poisoning: prefix malicioso
└── Response hijacking: RQP ou cache poisoning
```

---

## 💰 Modelo Econômico

### Estimativas de Custo (Claude API)
- **Reconnaissance**: $0.30-0.50 per target
- **Detection**: $0.50-1.00 per target  
- **Validation**: $0.20-0.40 per finding
- **Exploitation**: $1.00-3.00 per validated vulnerability
- **Learning**: $0.10-0.20 per execution

### ROI Projections
Baseado na research "HTTP/1.1 Must Die":
- **James Kettle**: $200k+ em 2 semanas (manual)
- **Team research**: $350k+ total reportado
- **DesyncHunter target**: $50k+ mensal com automação

### Budget Allocation Strategy
- **70%**: Detection e validation (high-volume, low-cost)
- **20%**: Exploitation (medium-volume, medium-cost)
- **10%**: Learning e optimization (low-volume, high-value)

---

## 🔒 Considerações de Segurança e Compliance

### Ethical Hacking Guidelines
- **Apenas targets autorizados**: VDP ou bug bounty programs
- **No data exfiltration**: Foco em PoC, não em dados reais
- **Minimal impact**: Evitar DoS ou degradação de serviço
- **Responsible disclosure**: Reports através de canais oficiais

### Rate Limiting e Throttling
- **Request rate**: Max 10 req/second per target
- **Concurrent targets**: Max 5 simultâneos
- **Backoff strategy**: Exponential backoff em caso de errors
- **Respect robots.txt**: Quando aplicável

### Data Protection
- **No persistent storage**: de dados sensíveis dos targets
- **Encrypted logs**: Para debugging e learning
- **Anonymized reporting**: Remove informações identificáveis
- **GDPR compliance**: Para targets europeus

---

## 📚 Referências e Bibliografia

### Research Papers
1. **"HTTP/1.1 Must Die - The Desync Endgame"** - James Kettle, 2025
2. **"HTTP Desync Attacks: Request Smuggling Reborn"** - James Kettle, 2019
3. **"Practical HTTP Header Smuggling"** - Daniel Thacher, 2021
4. **"TE.0 Request Smuggling"** - Paolo Arnolfo et al., 2024

### Tools e Frameworks
1. **HTTP Request Smuggler v3.0** - PortSwigger Research
2. **Turbo Intruder** - PortSwigger Research  
3. **Burp Suite** - Professional testing platform
4. **Claude API** - Anthropic AI platform

### Bug Bounty Programs Relevantes
1. **HackerOne**: Múltiplos programs com HTTP smuggling scope
2. **Bugcrowd**: Enterprise programs focados em infrastructure
3. **T-Mobile**: $12k bounty para Expect-based desync
4. **GitLab**: $7k bounty para RQP via obfuscated Expect
5. **Akamai**: $9k bounty para CDN-wide vulnerability

## 🤝 Contributing

### Development Guidelines
- Code style: Black formatter
- Type hints: Required para todas as functions
- Documentation: Docstrings para todos os modules
- Testing: Tests obrigatórios para novas features

### Research Contributions
- Novas técnicas de desync bem-vindas
- Improvements em detection accuracy
- Otimizações de performance
- Integration com outras tools

---

## ⚖️ Legal Disclaimer

**DesyncHunter** é uma ferramenta de pesquisa de segurança destinada exclusivamente para:
- Programas de bug bounty autorizados
- Vulnerability Disclosure Programs (VDPs)
- Penetration testing autorizado
- Pesquisa de segurança ética

**É responsabilidade do usuário**:
- Obter autorização apropriada antes do uso
- Cumprir todos os termos dos programs de bug bounty
- Seguir práticas de ethical hacking
- Respeitar leis locais e internacionais

Os desenvolvedores não se responsabilizam pelo uso inadequado desta ferramenta.

---

## 📄 License

MIT License - Ver LICENSE file para detalhes completos.

---

**DesyncHunter** - *Hunting HTTP/1.1 vulnerabilities with artificial intelligence*

*"More desync attacks are always coming. Let's find them first."* - Inspired by James Kettle's research