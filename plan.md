# VibeGuard

## AI-Powered Security Testing Platform for Vibe-Coded Applications

You are the lead security engineer, ML/LLM engineer, application-security researcher, and software architect responsible for building a research-grade security testing platform called **VibeGuard**.

The objective is NOT to reinvent existing security scanners.

Your objective is to integrate mature open-source security tooling into one coherent platform and build our original research layer on top of it.

The primary research contribution is:

> **AIAG — Authorization-Intent Attack Graph**

AIAG combines statically inferred authorization intent with dynamically observed application behavior to identify authorization contradictions such as IDOR/BOLA, privilege escalation, and broken access control.

The broader platform should additionally test conventional web vulnerabilities and AI-specific vulnerabilities such as prompt injection and insecure agent/tool behavior.

---

# 1. PRODUCT VISION

Build a platform that allows a developer to submit a vibe-coded / AI-generated application and receive a security assessment.

Input:

* GitHub repository
* local source archive
* optionally deployed URL
* optionally Docker Compose application
* optionally authentication credentials for test accounts

Output:

* discovered application architecture
* discovered endpoints
* discovered authentication/authorization mechanisms
* discovered AI/LLM integrations
* vulnerabilities
* evidence
* reproduction steps
* source-code locations
* runtime requests/responses
* confidence
* severity
* remediation suggestions

The platform should support:

```text
                VibeSec
                   |
          Application Intake
                   |
          Application Discovery
                   |
       +-----------+-----------+
       |                       |
       v                       v
   Static Analysis        Runtime Analysis
       |                       |
       v                       v
      SAST                    DAST
       |                       |
       +-----------+-----------+
                   |
                   v
            Application Graph
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
    AIAG       Web Security   AI Security
       |           |           |
       v           v           v
   IDOR/BOLA     SQLi/XSS     Prompt Injection
   Auth Bypass   SSRF/CSRF    Tool Abuse
   Privilege     Secrets      Data Leakage
   Escalation    Misconfig    RAG Injection
       |           |           |
       +-----------+-----------+
                   |
                   v
            Verification Engine
                   |
                   v
              Evidence Store
                   |
                   v
             Security Report
```

---

# 2. NON-NEGOTIABLE RESEARCH PRINCIPLE

Do not make the system an "LLM that guesses vulnerabilities."

Every important finding must ideally contain:

```text
Finding
├── vulnerability type
├── severity
├── affected endpoint/resource
├── source-code evidence
├── static-analysis evidence
├── runtime evidence
├── request
├── response
├── authentication identity
├── resource ownership
├── reproduction procedure
├── confidence
└── remediation
```

The system should distinguish:

```text
Potential
Suspicious
Confirmed
Verified
```

Do not label a vulnerability "verified" merely because an LLM says it exists.

Verification must be based on reproducible evidence.

---

# 3. SAFETY BOUNDARY

The platform is intended for authorized security testing of applications.

Implement explicit authorization boundaries.

The scanner must support:

* localhost
* local Docker environments
* explicitly authorized staging environments
* applications owned by the user/team

Do NOT design the system around uncontrolled internet-wide scanning.

Include:

```text
Target authorization confirmation
Scope restrictions
Allowed host configuration
Rate limits
Request limits
Concurrency limits
Kill switch
Audit logging
```

All active testing must remain inside explicitly configured targets.

---

# 4. FIRST TASK — DO NOT CODE YET

Before implementing anything, inspect the current open-source ecosystem.

You must research and evaluate existing projects for:

## Static analysis

Investigate:

* Semgrep
* Joern
* CodeQL
* tree-sitter
* framework-specific AST tools

## Web crawling / browser automation

Investigate:

* Playwright
* Crawlee
* Katana

## DAST

Investigate:

* OWASP ZAP
* Nuclei
* Caido-compatible workflows if licensing/integration permits
* existing open-source web vulnerability scanners

## API discovery

Investigate:

* OpenAPI parsers
* Swagger/OpenAPI discovery
* GraphQL introspection
* browser/network interception

## Authentication testing

Investigate existing open-source authentication/session tooling.

## LLM security

Investigate current open-source projects for:

* prompt injection testing
* LLM red teaming
* RAG security
* agent security
* tool-use security
* system-prompt leakage
* indirect prompt injection

Examples to investigate include:

* Garak
* PyRIT
* Promptfoo
* Giskard
* relevant OWASP GenAI projects

Do not automatically adopt any tool.

For each candidate evaluate:

```text
maintenance
license
language
API availability
CLI availability
Docker support
extensibility
accuracy
community adoption
security
integration difficulty
research suitability
```

Create:

```text
docs/TOOL_SELECTION.md
```

with a table:

| Capability   | Candidate | Selected | Reason | License | Integration |
| ------------ | --------- | -------- | ------ | ------- | ----------- |
| SAST         | ...       | ...      | ...    | ...     | ...         |
| DAST         | ...       | ...      | ...    | ...     | ...         |
| Browser      | ...       | ...      | ...    | ...     | ...         |
| LLM security | ...       | ...      | ...    | ...     | ...         |

Prefer existing mature open-source components.

Do not implement functionality that an appropriate mature tool already provides.

---

# 5. REPOSITORY ARCHITECTURE

Create a monorepo approximately like:

```text
vibesec/
│
├── apps/
│   ├── web/
│   │   ├── frontend/
│   │   └── backend/
│   │
│   └── api/
│
├── services/
│   ├── orchestrator/
│   ├── discovery/
│   ├── crawler/
│   ├── sast/
│   ├── dast/
│   ├── authz/
│   ├── ai-security/
│   ├── aiag/
│   ├── verification/
│   ├── reporting/
│   └── evidence/
│
├── packages/
│   ├── schemas/
│   ├── graph/
│   ├── security-model/
│   ├── llm/
│   ├── logging/
│   └── evaluation/
│
├── benchmarks/
│   ├── fixtures/
│   ├── vibeapps/
│   └── ground_truth/
│
├── experiments/
│
├── research/
│
├── docs/
│
├── infra/
│   ├── docker/
│   └── compose/
│
├── tests/
│
└── README.md
```

Use a modular architecture.

Do not create a giant monolithic scanner.

---

# 6. TECHNOLOGY STACK

Use the following as the default architecture unless research of existing components suggests a better option.

## Frontend

Use:

* React
* TypeScript
* Vite or Next.js
* Tailwind CSS
* a component library only where useful

The UI should feel like a serious security product rather than a generic admin dashboard.

## Backend

Prefer:

* Python
* FastAPI
* Pydantic
* asyncio where appropriate

## Task execution

Use a queue/orchestrator suitable for long-running security scans.

Evaluate:

* Celery
* Redis Queue
* Temporal
* lightweight Redis-based orchestration

Choose based on actual project complexity.

## Database

Use PostgreSQL.

Use JSONB for flexible security evidence.

Use a graph database only if justified.

Do NOT introduce Neo4j simply because the project uses a graph concept.

AIAG can initially be represented using PostgreSQL relational tables plus graph traversal logic.

Evaluate Neo4j later.

## Browser

Use Playwright.

## Containers

Every target application and potentially dangerous scanner should run in isolated Docker containers.

---

# 7. APPLICATION INGESTION

Support:

```text
GitHub repository
ZIP
local project
Docker Compose
deployed authorized URL
```

After ingestion:

```text
Repository
    |
    v
Framework Detection
    |
    +--> frontend
    +--> backend
    +--> database
    +--> auth
    +--> APIs
    +--> AI integrations
    +--> external services
    +--> secrets/config
```

Detect common frameworks:

```text
Next.js
React
Express
FastAPI
Flask
Django
NestJS
Laravel
Supabase
Firebase
```

Do not attempt to support every framework initially.

Start with the most common AI-generated application stacks.

---

# 8. APPLICATION DISCOVERY ENGINE

Build a structured application inventory.

Example:

```json
{
  "application": {
    "framework": "Next.js",
    "language": "TypeScript"
  },
  "endpoints": [],
  "database": [],
  "authentication": [],
  "authorization": [],
  "llm_integrations": [],
  "tools": [],
  "external_services": []
}
```

Detect:

* API routes
* server actions
* database queries
* authentication middleware
* authorization checks
* role checks
* ownership checks
* file uploads
* external API calls
* LLM calls
* vector databases
* agent/tool definitions
* prompt templates

---

# 9. SAST ENGINE

Integrate mature tools instead of implementing a custom static analyzer for everything.

Use Semgrep/Joern/CodeQL where appropriate.

The SAST engine should produce normalized findings.

Example:

```json
{
  "finding_type": "missing_authorization_check",
  "file": "app/api/orders/[id]/route.ts",
  "line": 42,
  "endpoint": "/api/orders/:id",
  "resource": "Order",
  "evidence": "...",
  "confidence": 0.91
}
```

The SAST engine should specifically extract authorization intent.

---

# 10. AUTHORIZATION INTENT EXTRACTION

This is a central component.

Extract:

### Authentication requirements

```text
public
authenticated
admin
staff
service
unknown
```

### Authorization requirements

```text
role
permission
ownership
tenant
resource relationship
custom predicate
```

### Resource

```text
User
Order
Document
Project
Invoice
Message
etc.
```

### Action

```text
CREATE
READ
UPDATE
DELETE
EXECUTE
ADMIN
```

Represent the result as structured authorization intent.

Example:

```json
{
  "endpoint": "GET /api/orders/:id",
  "resource": "Order",
  "action": "READ",
  "auth_level": "authenticated",
  "ownership": {
    "required": true,
    "field": "user_id",
    "principal_field": "user.id"
  },
  "evidence": [
    {
      "file": "app/api/orders/[id]/route.ts",
      "line": 42
    }
  ]
}
```

---

# 11. AIAG

Implement the Authorization-Intent Attack Graph.

The graph contains:

```text
Principal
Role
Permission
Endpoint
Action
Resource
Resource Instance
Authentication State
Authorization Requirement
Runtime State
Observation
Contradiction
Finding
Evidence
```

Relationships:

```text
Principal -> HAS_ROLE -> Role

Role -> HAS_PERMISSION -> Permission

Permission -> ALLOWS -> Endpoint

Endpoint -> PERFORMS -> Action

Action -> TARGETS -> Resource

Resource -> OWNED_BY -> Principal

Endpoint -> REQUIRES -> AuthorizationRequirement

RuntimeObservation -> OBSERVES -> Endpoint

RuntimeObservation -> ACCESSES -> ResourceInstance

Observation -> CONTRADICTS -> AuthorizationRequirement

Contradiction -> PRODUCES -> Finding
```

---

# 12. RUNTIME STATE CAPTURE

Use Playwright and suitable crawling tools.

Capture:

```text
URL
method
headers
cookies
request body
response status
response body hash
DOM state
authenticated identity
session
resource identifiers
navigation state
API calls
```

Do not store secrets unnecessarily.

Redact:

```text
passwords
API keys
session secrets
authorization tokens
personal data
```

---

# 13. MULTI-IDENTITY TESTING

Authorization vulnerabilities require multiple identities.

The platform should support:

```text
anonymous
user A
user B
admin
```

where test accounts are explicitly supplied by the user or created inside controlled benchmark applications.

Example:

```text
User A
User B
Admin
```

Then test:

```text
A -> A resource
A -> B resource
B -> A resource
Admin -> A resource
```

This becomes extremely important for BOLA/IDOR detection.

---

# 14. AIAG CONTRADICTION ENGINE

Implement deterministic contradiction checks first.

Example:

Expected:

```text
GET /orders/:id
authenticated = true
ownership = true
```

Observed:

```text
authenticated = true
principal = user_A
resource_owner = user_B
response = 200
```

Generate:

```text
Authorization contradiction
```

Formalize the rule:

```text
ExpectedAccess(principal, resource) = FALSE

ObservedAccess(principal, resource) = TRUE

Therefore:

Contradiction(principal, resource) = TRUE
```

Do not allow an LLM to directly determine this final state.

The LLM may assist with:

* extracting intent
* identifying semantic relationships
* generating test cases
* explaining evidence

But deterministic evidence should drive verification.

---

# 15. WEB VULNERABILITY ENGINE

Integrate existing mature scanners.

Support initially:

```text
SQL Injection
XSS
SSRF
CSRF
Security headers
Secrets
Exposed debug endpoints
Insecure CORS
Authentication issues
Common API misconfigurations
```

Use existing scanners wherever possible.

Normalize their output into our schema:

```json
{
  "type": "xss",
  "severity": "high",
  "source": "scanner_name",
  "endpoint": "...",
  "evidence": {},
  "verification_status": "potential"
}
```

Do not blindly trust scanner output.

---

# 16. AI SECURITY ENGINE

Build a separate module for AI applications.

Detect whether the application contains:

```text
LLM
RAG
vector database
agent
tool calling
function calling
external actions
file/document ingestion
web browsing
email integration
database tools
code execution
```

Construct:

```text
User Input
    |
    v
Prompt
    |
    v
LLM
    |
    +---- RAG
    |
    +---- Tool
    |
    +---- External API
    |
    v
Response
```

---

# 17. PROMPT INJECTION TESTING

Integrate a mature LLM-security framework where suitable.

Investigate and potentially integrate:

* Garak
* PyRIT
* Promptfoo
* Giskard
* relevant OWASP GenAI tooling

Do not recreate their entire attack corpus.

Build an adapter.

Test:

### Direct prompt injection

```text
instruction override
role manipulation
instruction extraction
policy bypass
```

### Indirect prompt injection

Inject malicious content into:

```text
documents
RAG data
web pages
emails
database records
uploaded files
```

Then observe whether the model follows untrusted instructions.

---

# 18. AGENT / TOOL SECURITY

Detect:

```text
LLM
 |
 +--> database
 +--> filesystem
 +--> shell
 +--> email
 +--> HTTP
 +--> payment
 +--> cloud API
```

Model:

```text
Untrusted Input
      |
      v
      LLM
      |
      v
Privileged Tool
      |
      v
Sensitive Action
```

Flag cases where untrusted content can directly cause privileged operations without adequate authorization or confirmation.

---

# 19. EVIDENCE ENGINE

Every scanner must produce evidence.

Define a common evidence schema.

```json
{
  "evidence_id": "EV-00001",
  "finding_id": "F-00001",
  "source_code": [],
  "requests": [],
  "responses": [],
  "runtime_trace": [],
  "screenshots": [],
  "logs": [],
  "observations": []
}
```

Evidence must be immutable after experiment completion.

---

# 20. VERIFICATION ENGINE

This is one of the most important platform components.

Pipeline:

```text
Scanner Finding
      |
      v
Evidence Collection
      |
      v
Exploit/Reproduction Attempt
      |
      v
Independent Verification
      |
      v
Verified Finding
```

Status:

```text
potential
suspicious
confirmed
verified
rejected
```

A finding should become "verified" only when sufficient evidence exists.

---

# 21. LLM ORCHESTRATOR

Use an LLM where reasoning is genuinely useful.

The LLM can:

```text
understand code
extract authorization semantics
generate test hypotheses
interpret API behavior
correlate evidence
explain findings
generate remediation
```

The LLM must NOT be trusted blindly for:

```text
final vulnerability confirmation
statistical calculations
ground-truth labeling
authorization proof
```

Use structured JSON outputs.

Implement:

```text
LLM provider abstraction

OpenAI-compatible
Anthropic-compatible
Google-compatible
local models
```

Do not hard-code one model into the architecture.

Record:

```text
model
version
prompt
temperature
parameters
tokens
latency
cost
response
```

---

# 22. SECURITY GRAPH

Build a normalized application security graph.

Core entities:

```text
Application
Repository
File
Endpoint
HTTP Request
HTTP Response
User
Role
Permission
Resource
Resource Instance
Database
Table
Column
LLM
Prompt
Document
Tool
External Service
Finding
Evidence
```

This graph should allow questions such as:

```text
Which endpoints access resources without ownership checks?

Which resources can User A access as User B?

Which LLMs consume untrusted documents?

Which tools are reachable from user-controlled input?

Which privileged actions are reachable through an agent?

Which findings have both static and dynamic evidence?
```

---

# 23. REPORTING

Build a professional security report.

For every vulnerability:

```text
Title
Severity
Confidence
Status
Affected Component

Description

Why it matters

Evidence

Source code

Runtime behavior

Attack path

Reproduction steps

Impact

Recommended fix
```

For AIAG:

```text
Authorization Intent
        |
        v
Expected behavior
        |
        v
Observed behavior
        |
        v
Contradiction
        |
        v
Verified vulnerability
```

---

# 24. FRONTEND

Build these screens.

## Dashboard

```text
Applications
Active scans
Findings
Severity distribution
Verification status
```

## Application Overview

```text
Framework
Endpoints
Database
Authentication
LLM integrations
Tools
Security posture
```

## Scan

```text
Discovery
SAST
DAST
AI Security
AIAG
Verification
Report
```

## Attack Graph

Interactive visualization.

Allow the user to see:

```text
User
 → Role
 → Permission
 → Endpoint
 → Resource
 → Database
```

and:

```text
User
 → Input
 → LLM
 → Tool
 → Sensitive Action
```

## Findings

Filter:

```text
severity
type
verified
endpoint
engine
confidence
```

## Finding Detail

Show complete evidence.

---

# 25. DATABASE

Design PostgreSQL schema for:

```text
applications
scans
scan_tasks
repositories
endpoints
users
roles
permissions
resources
authorization_intents
runtime_observations
graph_nodes
graph_edges
findings
evidence
requests
responses
llm_calls
tool_calls
experiments
```

Use UUIDs.

Use JSONB where schema flexibility is useful.

---

# 26. EXPERIMENT INFRASTRUCTURE

This is a research project.

Every experiment must record:

```text
experiment ID
application
benchmark
baseline
model
model version
prompt
configuration
trial
timestamp
result
raw output
evidence
tokens
cost
runtime
```

Never overwrite raw experiment results.

---

# 27. BENCHMARK — VibeBench

Create a benchmark specifically for AI-generated applications.

Start with 15–20 carefully constructed applications.

Each application should have:

```text
application source
deployment configuration
authentication accounts
authorization policy
ground truth
vulnerability type
exploit procedure
expected evidence
```

Initial categories:

```text
BOLA
IDOR
missing authorization
role escalation
tenant isolation
SQL injection
XSS
SSRF
prompt injection
indirect prompt injection
tool abuse
data leakage
```

Ground truth must be manually verified.

---

# 28. RESEARCH EXPERIMENTS

The primary research experiments should test:

## Experiment 1

```text
AIAG
vs
dynamic-only
```

Does authorization intent improve detection?

## Experiment 2

```text
AIAG
vs
static-only
```

Does runtime behavior improve detection?

## Experiment 3

```text
AIAG
vs
LLM-only
```

Does structured authorization reasoning outperform generic LLM judgment?

## Experiment 4

```text
AIAG
vs
existing security agents
```

Evaluate on common benchmark subsets.

## Experiment 5

Ablate:

```text
without graph
without static analysis
without runtime state
without LLM
```

---

# 29. METRICS

Measure:

```text
Precision
Recall
F1
False Positive Rate
False Negative Rate
Detection Rate
Verification Rate
Time to Detection
Cost per Application
Requests per Application
LLM Tokens
```

For authorization specifically:

```text
BOLA detection rate
IDOR detection rate
Privilege escalation detection rate
```

---

# 30. STATISTICAL RIGOR

Never calculate confidence intervals from fabricated or smooth values.

Store raw per-example results.

Use real bootstrap resampling where appropriate.

For every reported metric:

```text
raw observations
      |
      v
aggregation
      |
      v
bootstrap
      |
      v
confidence interval
```

Use at least 10 independent trials where stochasticity makes repeated trials necessary.

Record the random seed where applicable.

---

# 31. INTERNAL VALIDATION

Before any number enters a paper:

1. Check raw experiment logs.
2. Re-run the experiment.
3. Check ground truth.
4. Independently verify a sample of findings.
5. Confirm statistical calculation.
6. Confirm denominator.
7. Confirm whether the result is synthetic or real.
8. Confirm that the table and text use the same numbers.

Maintain:

```text
research/CLAIM_EVIDENCE_MATRIX.md
```

Format:

```text
Claim
|
+-- Experiment ID
+-- Raw data
+-- Analysis script
+-- Figure/Table
+-- Evidence
+-- Reviewer notes
```

---

# 32. DEVELOPMENT ORDER

Do NOT implement all modules simultaneously.

Follow exactly this order:

## Stage 0

Tool research and selection.

Deliver:

```text
docs/TOOL_SELECTION.md
```

## Stage 1

Repository + Docker + PostgreSQL + FastAPI + frontend.

Deliver:

```text
hello application
```

## Stage 2

Application ingestion.

Deliver:

```text
repository → application inventory
```

## Stage 3

Endpoint discovery.

Deliver:

```text
application → endpoint inventory
```

## Stage 4

Playwright runtime crawler.

Deliver:

```text
application → runtime observations
```

## Stage 5

SAST integration.

Deliver:

```text
source → normalized findings
```

## Stage 6

Authorization intent extraction.

Deliver:

```text
source → authorization intent
```

## Stage 7

AIAG.

Deliver:

```text
authorization intent
+
runtime state
→ contradiction
```

## Stage 8

BOLA/IDOR verification.

Deliver:

```text
candidate → reproducible evidence
```

## Stage 9

Existing DAST integration.

Deliver:

```text
SQLi
XSS
SSRF
CSRF
etc.
```

## Stage 10

AI security engine.

Deliver:

```text
prompt injection
RAG injection
tool abuse
data leakage
```

## Stage 11

Unified security graph.

## Stage 12

Dashboard/reporting.

## Stage 13

VibeBench.

## Stage 14

Research evaluation.

---

# 33. ENGINEERING RULES

Follow these rules throughout development.

### Rule 1

Do not reinvent mature security tooling.

### Rule 2

Do not use an LLM when deterministic logic is sufficient.

### Rule 3

Do not make an LLM the sole source of vulnerability confirmation.

### Rule 4

Every important result must have evidence.

### Rule 5

Every scanner must expose structured output.

### Rule 6

Every experiment must preserve raw data.

### Rule 7

Every vulnerability detector must be independently testable.

### Rule 8

Every external tool must be wrapped behind an adapter.

For example:

```text
SASTAdapter
DASTAdapter
CrawlerAdapter
LLMSecurityAdapter
```

This allows tools to be replaced later.

### Rule 9

Do not hard-code a single LLM provider.

### Rule 10

Do not prematurely optimize.

---

# 34. TESTING

Write tests for every layer.

Unit tests:

```text
authorization parser
graph construction
contradiction algorithm
finding normalization
severity calculation
evidence generation
```

Integration tests:

```text
repository → discovery
discovery → SAST
SAST → AIAG
AIAG → runtime
runtime → verification
```

End-to-end test:

```text
vulnerable demo application
        |
        v
VibeSec
        |
        v
BOLA
        |
        v
verified finding
```

Create intentionally vulnerable fixture applications.

Never test the system primarily against production applications.

---

# 35. FIRST DEMO APPLICATION

Before scanning arbitrary applications, create:

```text
benchmarks/fixtures/vulnshop/
```

It should contain:

```text
Users
Orders
Admin
Documents
AI assistant
```

Intentional vulnerabilities:

```text
BOLA
IDOR
missing role check
SQL injection
XSS
prompt injection
indirect prompt injection
tool abuse
```

The system should eventually discover these automatically.

This becomes our canonical integration test.

---

# 36. DEFINITION OF DONE FOR MVP

The MVP is complete when:

```text
User submits application
        ↓
VibeSec discovers application
        ↓
Endpoints identified
        ↓
Source analyzed
        ↓
Runtime explored
        ↓
Authorization intent extracted
        ↓
AIAG constructed
        ↓
BOLA/IDOR candidate identified
        ↓
Attack reproduced
        ↓
Evidence collected
        ↓
Verified finding displayed
```

Additionally:

```text
SQLi/XSS/SSRF
```

can be detected through integrated existing tooling.

And:

```text
prompt injection
```

can be tested for applications containing LLM functionality.

---

# 37. DEFINITION OF DONE FOR RESEARCH PROTOTYPE

The research prototype is complete when:

* AIAG works on controlled applications.
* VibeBench exists.
* Baselines are reproducible.
* Raw experiment data is preserved.
* Ablation experiments are complete.
* AIAG is compared against meaningful baselines.
* statistical analysis is reproducible.
* findings have independent verification.
* all paper claims map to experiment IDs.

---

# 38. WHAT NOT TO BUILD YET

Do NOT initially build:

```text
custom graph database
custom browser
custom crawler
custom SAST engine
custom SQL injection scanner
custom XSS scanner
custom prompt injection corpus
custom LLM
custom authentication system
distributed Kubernetes architecture
complex multi-agent swarm
```

First integrate existing tools.

Only implement custom components where they provide research value.

---

# 39. INITIAL MILESTONE

Your first milestone is NOT:

"Build VibeSec."

It is:

> **Build a reproducible end-to-end pipeline that takes one deliberately vulnerable AI-generated application and automatically discovers and verifies one BOLA vulnerability using static authorization intent + runtime testing.**

Everything else comes after this.

The first successful pipeline should look like:

```text
VulnShop
   |
   v
Application Discovery
   |
   v
SAST
   |
   v
Authorization Intent
   |
   v
AIAG
   |
   v
Playwright Runtime Test
   |
   v
Cross-User Access
   |
   v
Contradiction
   |
   v
Verification
   |
   v
Evidence
   |
   v
Verified BOLA
```

Once this works reliably, expand the system.

---

# 40. YOUR IMMEDIATE ACTION

Start by completing only these files:

```text
README.md

docs/
├── ARCHITECTURE.md
├── TOOL_SELECTION.md
├── THREAT_MODEL.md
├── RESEARCH_SPEC.md
└── VULNERABILITY_TAXONOMY.md

research/
├── NOVELTY_MATRIX.md
└── EVALUATION_PLAN.md
```

Do not implement the entire platform before these documents exist.

Then create:

```text
benchmarks/fixtures/vulnshop/
```

and use it as the first end-to-end target.

The project should evolve from:

```text
ONE VERIFIED VULNERABILITY
        ↓
ONE WORKING AIAG
        ↓
ONE REPRODUCIBLE PIPELINE
        ↓
MULTIPLE VULNERABILITIES
        ↓
VibeBench
        ↓
RESEARCH EVALUATION
        ↓
FULL VibeSec PLATFORM
```

The priority is **correctness and evidence over feature count**.