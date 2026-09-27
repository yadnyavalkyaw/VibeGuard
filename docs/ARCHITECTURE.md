# VibeGuard — System Architecture

## 1. Overview

VibeGuard is structured as a modular, decoupled micro-service platform wrapped inside a monorepo. It combines static source code analysis (SAST), dynamic application security testing (DAST), authorization intent extraction, multi-identity Playwright browser crawling, and GenAI security evaluation into a unified attack graph pipeline.

```text
               VibeGuard Platform Architecture
                            |
                   Application Intake
                            |
                   Discovery Service
                            |
        +-------------------+-------------------+
        |                                       |
        v                                       v
   Static Analysis Service              Runtime Analysis Service
   (Semgrep / Tree-sitter / AST)        (Playwright Crawling & DAST)
        |                                       |
        +-------------------+-------------------+
                            |
                            v
               AIAG Engine (Graph Builder)
                            |
        +-------------------+-------------------+
        |                   |                   |
        v                   v                   v
   Authz Contradictions   Web Security        AI Security
   (BOLA/IDOR/PrivEsc)   (SQLi/XSS/SSRF)    (Injection/Tools)
        |                   |                   |
        +-------------------+-------------------+
                            |
                            v
                   Verification Engine
                            |
                            v
                   Evidence Store & DB
                            |
                            v
                   UI / Security Report
```

---

## 2. Core Subsystems

### 2.1 Intake & Discovery (`services/discovery`)
- Analyzes repository directory structure or Docker Compose configs.
- Identifies framework types (Next.js, FastAPI, Express, Django, Flask, NestJS).
- Extracts routes, API parameters, database entities, authentication middleware, and LLM integrations.

### 2.2 Static Analysis & Authorization Intent Extractor (`services/sast`, `services/authz`)
- Invokes SAST tools (e.g. Semgrep, tree-sitter AST parsers) to identify endpoints and underlying code structures.
- Analyzes authorization guards, role requirements, ownership parameters (e.g., `req.user.id == resource.user_id`), and middleware definitions.
- Generates structured **Authorization Intents** specifying required principal privileges per action.

### 2.3 Multi-Identity Runtime Crawler & DAST (`services/crawler`, `services/dast`)
- Controls headless Playwright browser instances operating under distinct authenticated identities (e.g., `User A`, `User B`, `Admin`, `Anonymous`).
- Explores endpoints, captures network transactions (HTTP request/response bodies, headers, status codes), and indexes created resource IDs.
- Executes targeted DAST payloads (Nuclei, custom adapters) against discovered API routes.

### 2.4 AIAG Engine (`services/aiag`)
- Constructs a directed graph in PostgreSQL storing Principals, Roles, Endpoints, Actions, Resources, Requirements, and Runtime Observations.
- Evaluates access control contradictions using deterministic propositional rules:
  $$\text{ExpectedAccess}(P, R) = \text{FALSE} \land \text{ObservedAccess}(P, R) = \text{TRUE} \implies \text{Contradiction}(P, R) = \text{TRUE}$$

### 2.5 AI Security Engine (`services/ai-security`)
- Evaluates GenAI prompt injection, indirect prompt injection via RAG / uploaded documents, system prompt leakage, and unauthorized tool execution.

### 2.6 Verification Engine (`services/verification`)
- Re-executes exploit payloads independently to confirm findings.
- Assigns strict verification statuses: `potential`, `suspicious`, `confirmed`, `verified`, `rejected`.

### 2.7 Evidence Store & Reporting (`services/evidence`, `services/reporting`, `apps/web`)
- Persists immutable JSON evidence items (requests, responses, AST nodes, stack traces, screenshots).
- Provides visual interactive attack graph rendering and evidence reporting.

---

## 3. Technology Choices

| Component | Technology | Rationale |
|---|---|---|
| Frontend | React, TypeScript, Vite, Tailwind CSS | Fast responsive UI, rich modern aesthetic, state management |
| Backend API | Python, FastAPI, Pydantic, asyncio | Async I/O for concurrent scanners, native ML/LLM library ecosystem |
| Storage | PostgreSQL + JSONB | Relational stability for graph tables combined with flexible schema for evidence payload structures |
| Browser | Playwright | High reliability, request interception capabilities, multi-context authentication state management |
| Orchestration | Redis + Celery / Lightweight Queue | Task scheduling, background scan worker execution |
