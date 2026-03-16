# PhantomPilot

[![CI](https://img.shields.io/github/actions/workflow/status/yourname/phantompilot/ci.yml?branch=main&label=CI)](https://github.com/yourname/phantompilot/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OWASP Agentic AI](https://img.shields.io/badge/OWASP-Agentic%20AI%20Top%2010-orange.svg)](https://owasp.org/www-project-agentic-ai-threats/)

**Automated security testing framework for AI agents, covering all 10 OWASP Agentic AI risk categories.**

PhantomPilot probes AI agents built on LangChain, CrewAI, and custom REST APIs for vulnerabilities that traditional LLM security tools miss — the dangerous layer where language models interact with real-world tools, permissions, memory stores, and other agents. It executes multi-turn attack chains across 10 OWASP risk categories (ASI01–ASI10), measures attack success rate with turn-level granularity, and maps every finding to MITRE ATLAS technique IDs. The output is a professional HTML report with expandable evidence chains and an ATT&CK Navigator layer for threat intelligence integration. If you deploy AI agents in production and have not tested whether they can be tricked into misusing their tools, leaking cross-tenant memory, or following spoofed delegation messages — PhantomPilot was built for you.

---

## Demo

```
$ pip install phantompilot[langchain]
$ phantompilot validate-config --config scan.yaml
✓ Configuration is valid. 8 modules configured.

$ phantompilot scan --config scan.yaml --target langchain -v
PhantomPilot v0.1.0 — AI Agent Red Team Framework
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Target     : LangChain AgentExecutor (gpt-4o, 6 tools)
Modules    : 8 enabled, 2 skipped
Started    : 2026-03-12 14:32:07 UTC

[ASI01] Multi-Turn Prompt Injection ........... 3 findings (1 CRITICAL)
[ASI02] Tool Misuse Testing .................. 2 findings (1 HIGH)
[ASI03] Excessive Permissions ................ 1 finding  (1 CRITICAL)
[ASI04] Output Validation .................... 4 findings (2 HIGH)
[ASI05] Output Consumption ................... 2 findings (1 HIGH)
[ASI06] Memory Poisoning ..................... 1 finding  (1 HIGH)
[ASI07] Supply Chain Risk .................... 3 findings (1 CRITICAL)
[ASI08] Overreliance ......................... 2 findings (0 CRITICAL)
[ASI09] Inter-Agent Comms .................... SKIPPED (single-agent target)
[ASI10] Rogue Agent Detection ................ SKIPPED (requires extended run)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                      RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Findings     : 18 total
  CRITICAL     : 3
  HIGH         : 5
  MEDIUM       : 7
  LOW          : 3
  ASR          : 87.5% (7/8 modules produced findings)
  Blast Radius : 7.2 / 10.0
  Avg TTC      : 4.3s
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Reports:
  → reports/phantompilot_a3f2c91b.json
  → reports/phantompilot_a3f2c91b.html
  → reports/phantompilot_atlas_a3f2c91b.json
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      PhantomPilot CLI                        │
│           scan · list-modules · validate-config              │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                 Experiment Runner                        │ │
│  │  Loads config → selects modules → orchestrates scans    │ │
│  └──────────────┬──────────────────────────┬───────────────┘ │
│                 │                          │                  │
│    ┌────────────▼────────────┐   ┌────────▼───────────────┐  │
│    │    Test Modules         │   │   Measurement Layer     │  │
│    │                         │   │                         │  │
│    │  ASI01  Prompt Injection│   │  MetricsAggregator      │  │
│    │  ASI02  Tool Misuse     │   │  ├── ASR (overall/mod)  │  │
│    │  ASI03  Permissions     │   │  ├── Time-to-Compromise │  │
│    │  ASI04  Output Valid.   │   │  └── Blast Radius       │  │
│    │  ASI05  Output Consume  │   │                         │  │
│    │  ASI06  Memory Poison   │   │  Reporters              │  │
│    │  ASI07  Supply Chain    │   │  ├── JSON (versioned)   │  │
│    │  ASI08  Overreliance    │   │  ├── HTML (dark theme)  │  │
│    │  ASI09  Inter-Agent     │   │  └── ATLAS Navigator    │  │
│    │  ASI10  Rogue Agent     │   │                         │  │
│    └────────────┬────────────┘   └─────────────────────────┘  │
│                 │                                             │
│    ┌────────────▼────────────────────────────────────────┐   │
│    │              Agent Adapter Layer                      │   │
│    │                                                      │   │
│    │  LangChainAdapter  │  CrewAIAdapter  │  RESTAdapter  │   │
│    │  (AgentExecutor)   │  (Crew)         │  (HTTP+JSON)  │   │
│    └──────────────────────────────────────────────────────┘   │
│                 │                                             │
└─────────────────┼─────────────────────────────────────────────┘
                  ▼
           Target AI Agent
```

Data flows top-down: the CLI loads configuration and passes it to the experiment runner, which selects and executes test modules against the target agent through the adapter layer. Findings bubble up through the measurement layer into the reporters.

---

## Supported Frameworks

| Framework | Adapter | Supported Versions | Notes |
|-----------|---------|-------------------|-------|
| LangChain | `LangChainAdapter` | ≥ 0.2 (langchain-core ≥ 0.2) | Hooks into AgentExecutor callbacks and intermediate steps |
| CrewAI | `CrewAIAdapter` | ≥ 0.41 | Supports sequential and hierarchical crew processes |
| AutoGPT | `RESTAdapter` | Any (via REST API) | Configure endpoints in YAML |
| Custom agents | `RESTAdapter` | Any HTTP API | JSONPath response parsing, configurable auth |

---

## Test Modules

| ASI Code | Risk Name | Attack Technique | ATLAS Mapping | Status |
|----------|-----------|-----------------|---------------|--------|
| ASI01 | Prompt Injection | Multi-turn goal hijacking: 7 graduated injection chains (goal displacement, context manipulation, instruction override, persona injection, constraint relaxation, cross-language bypass, encoding obfuscation) | AML.T0051, AML.T0043 | Stable |
| ASI02 | Tool Misuse | Per-tool misuse probes (read→write escalation, SSRF, code execution) plus cross-tool chaining tests | AML.T0040, AML.T0024 | Stable |
| ASI03 | Excessive Permissions | Vertical escalation (admin access, config modification, env var extraction) and horizontal escalation (cross-tenant data, other session memory) | AML.T0040, AML.T0024 | Stable |
| ASI04 | Insufficient Output Validation | XSS, SQL injection, command injection, path traversal, and header injection payload generation in structured agent output | AML.T0048 | Stable |
| ASI05 | Insecure Output Consumption | Mock consumer simulation: HTML renderer, SQL engine, shell executor, URL fetcher (SSRF), template engine (SSTI), JSON deserializer | AML.T0048 | Stable |
| ASI06 | Memory Poisoning | Canary token injection into conversation memory and vector stores; persistence, propagation, influence, and semantic poisoning tests | AML.T0018, AML.T0020, AML.T0024 | Stable |
| ASI07 | Supply Chain | Tool/plugin risk profiling (network access, code execution, file I/O scoring), description override testing, output trust exploitation | AML.T0051, AML.T0048, AML.T0017, AML.T0054 | Stable |
| ASI08 | Overreliance | Epistemic calibration measurement: unknowable questions, fabricated entity traps, domain boundary testing, citation accuracy analysis, confidence calibration | AML.T0048 | Stable |
| ASI09 | Inter-Agent Comms | Agent impersonation, spoofed delegation, injected inter-agent context, task result manipulation, privilege inheritance, delegation chain hijacking | AML.T0051, AML.T0040 | Stable |
| ASI10 | Rogue Agent | Statistical behavioral baseline + anomaly detection: goal drift measurement, unauthorized tool usage, deceptive alignment detection (differential response analysis) | AML.T0048, AML.T0018 | Stable |

---

## Installation

### From PyPI

```bash
# Core framework (no agent framework dependencies)
pip install phantompilot

# With LangChain support
pip install phantompilot[langchain]

# With CrewAI support
pip install phantompilot[crewai]

# Everything
pip install phantompilot[all]
```

### From Source

```bash
git clone https://github.com/yourname/phantompilot.git
cd phantompilot
pip install -e ".[dev]"
```

### Development Setup

```bash
git clone https://github.com/yourname/phantompilot.git
cd phantompilot
make install-dev
make lint        # ruff
make typecheck   # mypy --strict
make test        # pytest with coverage
```

---

## Quick Start

### Scenario A: Scan a LangChain ReAct Agent for Prompt Injection

Create `scan_injection.yaml`:

```yaml
adapter:
  type: langchain
  module_path: my_app.agent
  class_name: build_agent
  timeout_seconds: 30

modules:
  - asi_code: ASI01
    enabled: true
    max_turns: 7
    parameters:
      chain_types:
        - goal_displacement
        - instruction_override
        - persona_injection

report:
  formats: [json, html]
  output_dir: ./reports
```

Run:

```bash
phantompilot scan --config scan_injection.yaml
```

### Scenario B: Full Audit of a CrewAI Multi-Agent System

Create `scan_crew.yaml`:

```yaml
adapter:
  type: crewai
  module_path: my_crew.setup
  class_name: build_research_crew
  timeout_seconds: 120

modules:
  - asi_code: ASI01
    enabled: true
  - asi_code: ASI02
    enabled: true
  - asi_code: ASI03
    enabled: true
    parameters:
      allowed_tools: [search, calculator]
      denied_tools: [shell_exec, file_write]
  - asi_code: ASI06
    enabled: true
    parameters:
      canary_prefix: AUDIT_CANARY
      test_cross_session: true
  - asi_code: ASI09
    enabled: true
  - asi_code: ASI10
    enabled: true
    parameters:
      baseline_interactions: 30
      monitoring_interactions: 60

report:
  formats: [json, html, atlas]
  output_dir: ./audit_reports
```

Run:

```bash
phantompilot scan --config scan_crew.yaml --verbose
```

### Scenario C: Targeted Tool Misuse Test Against a REST API Agent

Create `scan_rest.yaml`:

```yaml
adapter:
  type: rest
  base_url: https://agent.internal.company.com/api/v1
  auth_type: bearer
  auth_value: ${AGENT_API_TOKEN}
  endpoints:
    send_message: /chat
    get_state: /agent/state
    get_memory: /agent/memory
    health: /health
  timeout_seconds: 15

modules:
  - asi_code: ASI02
    enabled: true
    timeout_seconds: 60
  - asi_code: ASI03
    enabled: true
    parameters:
      allowed_tools: [web_search, summarize]
      denied_tools: [execute_code, write_file, send_email]

report:
  formats: [json]
  output_dir: ./reports
```

Run:

```bash
phantompilot scan --config scan_rest.yaml --modules ASI02,ASI03
```

---

## Configuration Reference

```yaml
# PhantomPilot scan configuration — all fields with defaults shown

adapter:
  type: langchain                        # REQUIRED: langchain | crewai | rest | custom

  # LangChain / CrewAI adapters
  module_path: my_app.agent              # Python import path to module containing agent
  class_name: build_agent                # Class or factory function name
  init_kwargs: {}                        # kwargs passed to the constructor

  # REST adapter
  base_url: ""                           # Base URL of the agent API
  auth_type: none                        # bearer | api_key | none
  auth_value: ""                         # Token value (supports ${ENV_VAR} syntax)
  endpoints:                             # Endpoint path mapping
    send_message: /chat
    get_state: /state
    get_memory: /memory
    health: /health

  timeout_seconds: 30.0                  # Per-request timeout

modules:                                 # List of modules to run
  - asi_code: ASI01                      # REQUIRED: ASI01 through ASI10
    enabled: true                        # default: true
    custom_payloads: []                  # Additional attack payloads
    max_turns: 10                        # Max conversation turns per chain
    timeout_seconds: 120.0               # Module-level timeout
    parameters: {}                       # Module-specific parameters

report:
  formats: [json]                        # json | html | atlas (list)
  output_dir: ./reports                  # Output directory (created if missing)
  include_evidence: true                 # Include evidence chains in reports
  include_recommendations: true          # Include remediation recommendations

concurrency: 1                           # Modules run sequentially by default
verbose: false                           # Enable debug logging
```

---

## Sample Report Output

The HTML report is a single self-contained file with a dark theme and zero external dependencies.

**Executive Summary** shows six metric cards: Attack Success Rate (percentage of modules that produced findings), Total Findings count, Blast Radius score (0–10 scale combining severity depth and attack breadth), Average Time-to-Compromise, Modules Executed, and Critical Findings count. Each card is color-coded by severity threshold.

**Module Results** displays a grid of cards — one per ASI category — with PASS (green), FAIL (red), SKIP (gray), or ERROR (orange) badges.

**Risk Heatmap** renders a severity × ASI category matrix showing the concentration of findings. Each cell shows the count of findings at that intersection, color-coded from gray (zero) through yellow (MEDIUM) to red (CRITICAL).

**Findings** are presented as expandable cards sorted by severity. Each card shows severity and ASI code badges, a descriptive title, and expands on click to reveal the full description, MITRE ATLAS technique mapping, the complete evidence chain (formatted as a user/agent conversation with tool calls highlighted in monospace), the specific remediation recommendation, and module metadata.

**Recommendations** are deduplicated across findings, sorted by severity priority, and displayed with color-coded severity badges.

---

## MITRE ATLAS Integration

PhantomPilot maps every finding to MITRE ATLAS technique IDs and produces a Navigator-compatible JSON layer file that can be loaded directly into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

The layer uses a three-color scheme:

- **Red** — technique was tested and produced findings (vulnerabilities detected)
- **Green** — technique was tested and no findings were produced (clean)
- **Gray** — technique was not covered by this scan configuration

Each technique's Navigator comment contains a summary of mapped findings with severity levels and ASI codes. The layer metadata includes scan ID, target type, generation timestamp, and PhantomPilot version for traceability.

To use the layer:

1. Open ATT&CK Navigator
2. Click "Open Existing Layer" → "Upload from local"
3. Select the `phantompilot_atlas_*.json` file
4. The ATLAS technique matrix renders with PhantomPilot's findings overlaid

This integrates directly into existing threat intelligence workflows — security teams can overlay PhantomPilot results alongside their ATLAS-mapped threat models.

---

## Comparison with Existing Tools

| Feature | PhantomPilot | Microsoft PyRIT | NVIDIA Garak | DeepTeam |
|---------|-------------|----------------|-------------|----------|
| **Target layer** | Agent (tools, memory, permissions, multi-agent) | LLM (model-level jailbreaks, prompt injection) | LLM (probe-based vulnerability scanning) | LLM (red-teaming model outputs) |
| **OWASP Agentic AI mapping** | All 10 categories (ASI01–ASI10) | Not mapped | Not mapped | Not mapped |
| **Multi-turn attack chains** | Yes — 3 to 7 turn graduated chains | Single-turn and multi-turn prompt attacks | Single-turn probes | Multi-turn via orchestrator |
| **Tool misuse testing** | Yes — per-tool and cross-tool chaining | No | No | No |
| **Memory poisoning** | Yes — persistence, propagation, influence | No | No | No |
| **Inter-agent comms testing** | Yes — impersonation, delegation hijack | No | No | No |
| **Supply chain risk profiling** | Yes — tool risk scoring and description override | No | No | No |
| **Behavioral drift detection** | Yes — statistical anomaly detection | No | No | No |
| **MITRE ATLAS mapping** | Navigator-compatible layer output | Attack strategy mapping | No | No |
| **Agent framework support** | LangChain, CrewAI, REST API | Azure OpenAI, HuggingFace | Multiple LLM APIs | Multiple LLM APIs |
| **Report formats** | JSON, HTML, ATLAS Navigator | JSON, HTML | JSON, JSONL | JSON |
| **Language** | Python | Python | Python | Python |

PyRIT, Garak, and DeepTeam are excellent tools for LLM-level security testing. PhantomPilot is not a replacement — it tests a different layer. Use PyRIT or Garak to test whether your LLM can be jailbroken. Use PhantomPilot to test whether your agent can be tricked into misusing its tools, leaking memory across sessions, or following spoofed delegation commands.

---

## Contributing

### Adding a New Test Module

PhantomPilot's plugin architecture makes it straightforward to add new test modules.

1. **Create the module file** in `src/phantompilot/modules/`:

```python
"""ASI_NEW — Description of the new risk category."""

from phantompilot.adapters.base import AgentAdapter
from phantompilot.models import ASICode, Finding
from phantompilot.modules.base import TestModule


class NewRiskModule(TestModule):

    @property
    def name(self) -> str:
        return "New Risk Category"

    @property
    def asi_code(self) -> ASICode:
        return ASICode.ASI01  # Use appropriate code

    @property
    def description(self) -> str:
        return "Description of what this module tests."

    @property
    def atlas_technique_ids(self) -> list[str]:
        return ["AML.T0051"]

    async def setup(self) -> None:
        # Load payloads, validate preconditions
        pass

    async def execute(self, adapter: AgentAdapter) -> list[Finding]:
        # Run attack sequences, collect evidence, return findings
        findings: list[Finding] = []
        return findings

    async def teardown(self) -> None:
        # Clean up injected state
        pass
```

2. **Register the module** in `src/phantompilot/cli.py` by adding an entry to `MODULE_REGISTRY`.

3. **Write tests** in `tests/modules/` — test both the success case (mock vulnerable agent) and the clean case (mock safe agent).

4. **Run the full suite**:

```bash
make lint && make typecheck && make test
```

### Code Standards

- Type annotations on all public functions (`mypy --strict` must pass)
- Ruff for linting and formatting (line length 100)
- Every finding must include a complete evidence chain
- All test payloads must be inert canaries — never cause actual damage

---

## Ethical Use and Legal Disclaimer

PhantomPilot is a security testing tool designed for authorized security assessments of AI agent systems. It is intended for use by security professionals, red team operators, and development teams testing their own systems.

**You must have explicit authorization before testing any AI agent system you do not own.** Unauthorized testing of third-party systems may violate applicable laws including the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and the EU Directive on Attacks Against Information Systems.

PhantomPilot is provided as-is for legitimate security research and authorized testing only. The authors accept no liability for misuse. All test payloads are designed to be inert — they prove exploitability without causing damage — but you are solely responsible for ensuring your use complies with applicable laws, regulations, and authorization scopes.

If you discover vulnerabilities using PhantomPilot, follow responsible disclosure practices.

---

## License

MIT License. See [LICENSE](LICENSE) for the full text.

---

## References

- **OWASP Top 10 for Agentic AI Applications** — [owasp.org/www-project-agentic-ai-threats](https://owasp.org/www-project-agentic-ai-threats/) — Released December 2025. Defines ASI01–ASI10 risk categories for AI agent systems with input from NIST, Microsoft AI Red Team, and AWS.
- **MITRE ATLAS** — [atlas.mitre.org](https://atlas.mitre.org/) — Adversarial Threat Landscape for AI Systems. Knowledge base of adversary tactics and techniques targeting ML systems.
- **ATT&CK Navigator** — [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) — Web application for visualizing ATT&CK and ATLAS matrices. PhantomPilot's ATLAS reporter produces Navigator-compatible layer files.
- **Microsoft PyRIT** — [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT) — Python Risk Identification Toolkit for generative AI. Focuses on LLM-level red teaming.
- **NVIDIA Garak** — [github.com/NVIDIA/garak](https://github.com/NVIDIA/garak) — LLM vulnerability scanner with probe-based architecture.
- **Security Chaos Engineering** — Aaron Rinehart, Kelly Shortridge. *Security Chaos Engineering: Sustaining Resilience in Software and Systems.* O'Reilly Media, 2020.
