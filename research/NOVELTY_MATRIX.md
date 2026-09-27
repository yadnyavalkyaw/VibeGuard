# Novelty Matrix — Research Positioning

This matrix explicitly positions VibeGuard against conventional application security tools and state-of-the-art LLM vulnerability scanners.

---

## 1. Feature Comparison Matrix

| Capability / Feature | Traditional SAST (Semgrep, SonarQube) | Traditional DAST (OWASP ZAP, Burp) | LLM Red-Teaming (Garak, PyRIT) | AI Security Agents | **VibeGuard (AIAG)** |
|---|---|---|---|---|---|
| **Code Intent Awareness** | High (static rules) | None (blackbox) | None | Medium (LLM guesswork) | **High (AST Intent Extraction)** |
| **Multi-Identity Testing** | None | Limited (manual/macro) | None | Low | **Native (Simultaneous User A, B, Admin)** |
| **BOLA/IDOR Detection Precision** | Low (high false positives) | Low (requires custom configuration) | N/A | Low (LLM hallucination risk) | **High (Deterministic Contradiction Engine)** |
| **GenAI / Tool Use Security** | None | None | High (Prompt Injection) | Medium | **High (Integrated GenAI Engine + Tool AST)** |
| **Reproducible Evidence Output** | Static Snippets | HTTP Request/Response | Text outputs | Chat responses | **Unified Graph + Immutable HTTP/DOM Proofs** |
| **No-LLM Verification Grounding** | Deterministic rules | Deterministic checks | Heuristic heuristics | Pure LLM opinion | **Deterministic Evidence Verification Engine** |

---

## 2. Key Research Differentiators

1. **Authorization-Intent Attack Graph (AIAG)**:
   - Existing tools evaluate authorization either purely statically (causing false positives when custom middleware exists) or dynamically without schema awareness. AIAG bridges this gap by statically modeling intended authorization constraints and mapping them directly against dynamic multi-identity observations.

2. **Deterministic Contradiction Engine vs. LLM Guessing**:
   - Rather than prompting an LLM "Is this API vulnerable to BOLA?", VibeGuard uses LLMs *only* for semantic extraction and hypothesis generation, relying on mathematical propositional graph contradictions to prove vulnerabilities deterministically.

3. **GenAI Tool-Use & RAG Injection Correlation**:
   - VibeGuard connects web API authorization boundaries with GenAI agent tool definitions, detecting attacks where prompt injection bypasses frontend application security guards.
