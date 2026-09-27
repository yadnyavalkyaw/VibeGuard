# Threat Model & Safety Boundaries

## 1. Safety & Scope Policy

VibeGuard is designed strictly for **authorized security testing** of applications owned or explicitly authorized by the operating user or team. Uncontrolled internet-wide scanning is strictly prohibited by systemic controls.

---

## 2. Authorization & Boundary Enforcement Controls

To ensure testing remains within safety boundaries, VibeGuard enforces:

1. **Explicit Target Whitelisting**:
   - `localhost` / `127.0.0.1` / `::1`
   - Local Docker Compose network aliases (e.g., `http://vulnshop:3000`)
   - Explicitly configured staging domains matching an ownership verification token.

2. **Rate & Request Constraints**:
   - Hard concurrency limits per target host (default: 5 concurrent connections).
   - Maximum requests-per-second throttle (default: 20 req/sec).
   - Total request count safety caps per scan run.

3. **Emergency Systems**:
   - **Kill Switch**: Instant termination signal (`SIGKILL`) sent to active scanners, browser instances, and sub-processes upon user request or unexpected out-of-scope redirect.
   - **Out-of-Scope Navigation Interception**: Playwright requests attempting to navigate outside the target domain are automatically aborted with code `BLOCKED_OUT_OF_SCOPE`.

4. **Audit Logging**:
   - Every HTTP request dispatched, payload sent, and AST file scanned is logged to immutable audit records with timestamp, source module, and target URL.

---

## 3. Target Application Threat Profile

Vibe-coded / AI-generated applications typically exhibit specific architectural anti-patterns due to rapid creation via LLM prompts:

| Vulnerability Vector | Cause in Vibe-Coded Apps | VibeGuard Detection Approach |
|---|---|---|
| **Broken Object Level Authorization (BOLA)** | LLM generates route handlers fetching database items by URL param (`/api/items/[id]`) without verifying `resource.user_id == current_user.id`. | AIAG intent extraction + multi-identity Playwright request replay. |
| **Broken Function Level Authorization (BFLA)** | LLM forgets authorization middleware on admin API routes (`/api/admin/users`). | SAST middleware check + Anonymous/User A HTTP probes. |
| **Direct Prompt Injection** | Untrusted user input concatenated directly into LLM prompts without sanitization. | `LLMSecurityAdapter` injection probe suites. |
| **Indirect Prompt Injection** | RAG pipelines loading untrusted documents or web data into system context. | Synthetic document poison probes into RAG ingestion endpoints. |
| **Insecure Agent Tool Execution** | LLMs given direct access to DB execution, shell scripts, or email senders without confirmation steps. | AST discovery of tool schemas + payload manipulation testing. |
| **Hardcoded Secrets** | LLM suggestions containing demo API keys, JWT secrets, or DB strings committed to source code. | Semgrep secret detection rules. |
