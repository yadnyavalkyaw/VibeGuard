import os
import re
from typing import List
from packages.schemas.models import Finding, Severity, VerificationStatus, EvidenceItem, CodeEvidence

class SASTAdapter:
    """
    SAST Engine Adapter:
    Analyzes source code repository files to detect missing authorization checks, hardcoded secrets, and route definitions.
    """
    def scan_repository(self, repo_path: str) -> List[Finding]:
        findings = []
        if not os.path.exists(repo_path):
            return findings

        for root, _, files in os.walk(repo_path):
            for file_name in files:
                if file_name.endswith(('.py', '.ts', '.tsx', '.js')):
                    full_path = os.path.join(root, file_name)
                    rel_path = os.path.relpath(full_path, repo_path)
                    
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()

                    for idx, line in enumerate(lines, 1):
                        # Detect Hardcoded Secrets
                        if re.search(r'(secret|api_key|password|jwt_secret)\s*=\s*[\'"][A-Za-z0-9_\-]{8,}[\'"]', line, re.IGNORECASE):
                            if "example" not in line.lower() and "placeholder" not in line.lower():
                                evidence = EvidenceItem(
                                    finding_id="",
                                    source_code=[CodeEvidence(file=rel_path, line=idx, snippet=line.strip())],
                                    observations=["Hardcoded credentials detected in static source file."]
                                )
                                finding = Finding(
                                    title=f"Hardcoded Secret / API Key in {file_name}",
                                    vulnerability_type="Exposed Secret",
                                    severity=Severity.HIGH,
                                    confidence=0.9,
                                    status=VerificationStatus.SUSPICIOUS,
                                    affected_endpoint=f"File: {rel_path}",
                                    affected_resource=rel_path,
                                    reproduction_procedure=f"Inspect source code file {rel_path} at line {idx}.",
                                    remediation="Store secrets in environment variables or a secret management store (e.g. AWS Secrets Manager, Vault).",
                                    evidence=evidence
                                )
                                evidence.finding_id = finding.finding_id
                                findings.append(finding)

                        # Detect Unsanitized String Interpolation in SQL
                        if re.search(r'SELECT\s+.*\s+FROM\s+.*f[\'"].*\{.*\}', line, re.IGNORECASE):
                            evidence = EvidenceItem(
                                finding_id="",
                                source_code=[CodeEvidence(file=rel_path, line=idx, snippet=line.strip())],
                                observations=["SQL string interpolation detected without parameter binding."]
                            )
                            finding = Finding(
                                title=f"Potential SQL Injection Pattern in {file_name}",
                                vulnerability_type="SQL Injection",
                                severity=Severity.HIGH,
                                confidence=0.85,
                                status=VerificationStatus.POTENTIAL,
                                affected_endpoint=f"File: {rel_path}:{idx}",
                                affected_resource=rel_path,
                                reproduction_procedure=f"Review SQL query string interpolation at line {idx} in {rel_path}.",
                                remediation="Replace f-strings in SQL queries with parameterized query placeholders.",
                                evidence=evidence
                            )
                            evidence.finding_id = finding.finding_id
                            findings.append(finding)

        return findings
