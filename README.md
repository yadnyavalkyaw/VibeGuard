# VibeGuard

## AI-Powered Security Testing Platform for Vibe-Coded Applications

VibeGuard is a research-grade security testing platform designed specifically for "vibe-coded" and AI-generated web applications. While conventional DAST and SAST tools focus on generic vulnerability signatures (e.g. SQLi, XSS), VibeGuard introduces the **Authorization-Intent Attack Graph (AIAG)** to detect dynamic privilege escalation, Broken Object Level Authorization (BOLA / IDOR), and context-aware GenAI security flaws.

---

## 🎯 Key Novelty: AIAG (Authorization-Intent Attack Graph)

The core research contribution of VibeGuard is **AIAG**:
- **Static Analysis**: Statically extracts implied authorization intent (resource models, ownership rules, role boundaries, API actions) from source code and server route definitions.
- **Dynamic Analysis**: Dynamically observes application behaviors across multiple concurrent test identities (Anonymous, User A, User B, Admin).
- **Contradiction Detection**: Merges intent and observation into a unified attack graph to deterministically identify contradictions (e.g., `ExpectedAccess(User_A, Resource_B) = FALSE`, but `ObservedAccess(User_A, Resource_B) = TRUE`).

---

## 🏗️ Repository Architecture

```text
vibesec/
├── apps/
│   ├── web/                     # React + TypeScript + Vite + Tailwind CSS (UI Dashboard)
│   └── api/                     # FastAPI core backend service
├── services/
│   ├── orchestrator/           # Scan lifecycle & workflow coordinator
│   ├── discovery/              # Framework detection & route parsing
│   ├── crawler/                # Playwright-based multi-identity crawler
│   ├── sast/                   # SAST integration (Semgrep / AST parsing)
│   ├── dast/                   # DAST integration (Nuclei / ZAP adapters)
│   ├── authz/                  # Authorization intent extractor
│   ├── ai-security/            # Prompt injection & tool abuse engines
│   ├── aiag/                   # Authorization-Intent Attack Graph engine
│   ├── verification/           # Reproducible evidence verification engine
│   ├── reporting/              # Structured security report generator
│   └── evidence/               # Evidence storage & normalization manager
├── packages/
│   ├── schemas/                # Shared Pydantic data models & contracts
│   ├── graph/                  # Graph data structure & traversal logic
│   ├── security-model/         # Vulnerability taxonomy & identity definitions
│   ├── llm/                    # Provider-agnostic LLM interface (OpenAI, Anthropic, Gemini)
│   ├── logging/                # Structured loggers
│   └── evaluation/             # Metrics, bootstrap confidence resampling, analysis
├── benchmarks/
│   ├── fixtures/
│   │   └── vulnshop/           # Canonical vulnerable test application
│   ├── vibeapps/               # Benchmark app repository
│   └── ground_truth/           # Verified vulnerability mappings
├── experiments/                # Raw experiment runs & statistical scripts
├── research/                   # Novelty matrix, claims, evaluation plans
├── docs/                       # Architectural & research documentation
└── infra/                      # Docker & Compose configurations
```

---

## 🚀 Quickstart

### Prerequisites
- Python 3.11+
- Node.js 18+ / pnpm or npm
- Docker & Docker Compose

### Initial Development Setup
```bash
# Clone and setup workspace
docker-compose -f infra/compose/docker-compose.yml up -d
```

---

## 📜 Non-Negotiable Principles

1. **No Guessing**: Every vulnerability finding must contain verifiable static/dynamic evidence, reproducible HTTP requests/responses, and strict confidence levels.
2. **Deterministic Proofs**: AI/LLM models suggest hypotheses and extract code intent; deterministic evidence validation proves vulnerabilities.
3. **Safety First**: Active scanning is restricted strictly to explicitly authorized targets (`localhost`, isolated Docker instances, authorized staging URLs).

---

## 📄 Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Tool Selection & Analysis](docs/TOOL_SELECTION.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Research Specification](docs/RESEARCH_SPEC.md)
- [Vulnerability Taxonomy](docs/VULNERABILITY_TAXONOMY.md)
- [Novelty Matrix](research/NOVELTY_MATRIX.md)
- [Evaluation Plan](research/EVALUATION_PLAN.md)
