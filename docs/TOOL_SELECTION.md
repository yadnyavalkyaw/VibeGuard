# Tool Selection & Ecosystem Evaluation

This document outlines the systematic evaluation of open-source security components considered for integration into VibeGuard. Per our core design rules, VibeGuard does **not** reinvent mature security scanners; instead, it wraps them in normalized adapter interfaces (`SASTAdapter`, `DASTAdapter`, `CrawlerAdapter`, `LLMSecurityAdapter`).

---

## 1. Tool Selection Matrix

| Capability | Candidate | Selected | Reason | License | Integration Approach |
|---|---|---|---|---|---|
| **SAST** | Semgrep | **Yes** | Fast rule-based semantic code matching, excellent AST support for TS/Python/Go | LGPL-2.1 | CLI / JSON output parsed via `SASTAdapter` |
| **SAST / AST** | Tree-sitter | **Yes** | Granular language parsing to extract authorization check AST blocks | MIT | Python bindings (`tree-sitter`) |
| **SAST** | CodeQL | No | Complex infrastructure, heavy runtime overhead for rapid local vibe-app scans | GHDL / Proprietary CLI | N/A |
| **SAST** | Joern | No | Requires JVM / CPG pipeline complexity, heavy memory footprint for small vibe apps | Apache-2.0 | N/A |
| **Browser Automation** | Playwright | **Yes** | Multi-context support (Simultaneous User A, User B, Admin sessions), network interception | Apache-2.0 | Python `playwright` async API |
| **Crawling** | Crawlee | No | Node.js native, excellent crawler but Playwright integration in Python backend is cleaner | Apache-2.0 | N/A |
| **Crawling** | Katana | Optional | Fast CLI crawler for passive JS link extraction | MIT | CLI adapter |
| **DAST** | Nuclei | **Yes** | Fast, template-driven active testing with structured JSON output | MIT | CLI execution in isolated runner |
| **DAST** | OWASP ZAP | Optional | Full proxy feature set, but heavy daemon requirements compared to Nuclei for MVP | Apache-2.0 | REST API client adapter |
| **API Discovery** | OpenAPI Generator / Parsers | **Yes** | Standardized parsing for OpenAPI v2/v3 schemas | Apache-2.0 | Python `openapi-parser` |
| **LLM Security** | Promptfoo | **Yes** | Lightweight, assertion-driven red teaming for prompts and GenAI apps | MIT | CLI / JSON adapter via `LLMSecurityAdapter` |
| **LLM Security** | Garak | **Yes** | Comprehensive LLM vulnerability scanner & prompt injection probing | Apache-2.0 | Python package / CLI wrapper |
| **LLM Security** | PyRIT | No | Azure-centric multi-turn red teaming framework, overly complex for single-app probes | MIT | N/A |
| **LLM Security** | Giskard | Optional | Good for tabular / RAG model evaluation, candidate for future RAG evaluation | Apache-2.0 | Python API |

---

## 2. Evaluation Criteria

Each candidate tool was evaluated against 12 key criteria:
1. **Maintenance**: Active commit history and security response team.
2. **License**: Permissive or standard open source (MIT, Apache-2.0, LGPL-2.1).
3. **Language**: Python or TypeScript compatibility preferred.
4. **API Availability**: Programmatic SDK or structured JSON outputs.
5. **CLI Availability**: Clean command-line interface for subprocess execution.
6. **Docker Support**: Pre-built docker images or lightweight container packaging.
7. **Extensibility**: Capability to inject custom rules, templates, or scripts.
8. **Accuracy**: High precision, minimal false positives on modern web stacks.
9. **Community Adoption**: Widespread industry use and established vulnerability coverage.
10. **Security**: Safe execution model without arbitrary remote code execution risks.
11. **Integration Difficulty**: Low overhead for containerized wrapping.
12. **Research Suitability**: Capability to provide granular data feeds into the AIAG graph.

---

## 3. Adapter Strategy

To prevent vendor lock-in and enable tool substitution without breaking core platform logic, all external engines are isolated behind standard interface adapters:

```python
class BaseAdapter(ABC):
    @abstractmethod
    async def run_scan(self, target_config: TargetConfig) -> List[NormalizedFinding]:
        pass
```

- `SASTAdapter`: Wraps Semgrep & Tree-sitter AST extractors.
- `CrawlerAdapter`: Wraps Playwright browser crawlers.
- `DASTAdapter`: Wraps Nuclei DAST scanners.
- `LLMSecurityAdapter`: Wraps Promptfoo and Garak injection probes.
