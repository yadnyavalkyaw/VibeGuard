import asyncio
import os
import json
from services.authz.intent_extractor import AuthorizationIntentExtractor
from services.crawler.multi_identity_crawler import MultiIdentityCrawler
from packages.graph.aiag_graph import AIAGraph
from services.verification.verification_engine import VerificationEngine
from services.dast.dast_engine import DASTEngine
from services.ai_security.ai_security_engine import AISecurityEngine

class VibeGuardPipeline:
    def __init__(self, target_code_path: str, target_base_url: str):
        self.target_code_path = target_code_path
        self.target_base_url = target_base_url
        self.crawler = MultiIdentityCrawler(target_base_url)
        self.graph = AIAGraph()
        self.verifier = VerificationEngine()
        self.dast_engine = DASTEngine(target_base_url)
        self.ai_security_engine = AISecurityEngine(target_base_url)

    async def run_pipeline(self):
        print("================================================================")
        print("[+] VibeGuard Security Scanner -- Complete Multi-Engine Pipeline")
        print("================================================================")

        all_findings = []

        # 1. Static Authorization Intent Extraction
        print("\n[Step 1] Extracting Static Authorization Intents...")
        extractor = AuthorizationIntentExtractor(self.target_code_path)
        intents = extractor.extract_intents()
        for intent in intents:
            print(f"  [-] Discovered Intent: {intent.http_method} {intent.endpoint} | Resource: {intent.resource} | Ownership Required: {intent.ownership.required}")
            self.graph.add_authorization_intent(intent)

        # 2. Multi-Identity Dynamic Crawling
        print("\n[Step 2] Executing Multi-Identity Dynamic Runtime Exploration...")
        observations = await self.crawler.crawl_target_app()
        for obs in observations:
            print(f"  [-] Observation: Principal={obs.principal_id} | Endpoint={obs.endpoint} | TargetRes={obs.target_resource_id} | Owner={obs.resource_owner_id} | Status={obs.status_code}")
            self.graph.add_runtime_observation(obs)

        # 3. AIAG Contradiction Evaluation
        print("\n[Step 3] Evaluating Authorization-Intent Attack Graph (AIAG)...")
        contradictions = self.graph.evaluate_contradictions()
        print(f"  [-] Contradictions Identified: {len(contradictions)}")
        for c in contradictions:
            print(f"     [!] {c.rule_violated}: {c.description}")

        # 4. Independent Verification Engine (Authz)
        print("\n[Step 4] Running Independent Verification Engine (AIAG Authz)...")
        authz_findings = self.verifier.verify_contradictions(contradictions)
        print(f"  [-] Verified Authz Findings: {len(authz_findings)}")
        all_findings.extend(authz_findings)

        # 5. DAST Scan (SQLi & XSS)
        print("\n[Step 5] Executing Active DAST Web Scanner Engine...")
        dast_findings = await self.dast_engine.run_dast_scan()
        print(f"  [-] Verified DAST Web Findings: {len(dast_findings)}")
        all_findings.extend(dast_findings)

        # 6. AI Security Scan (Prompt Injection & Tool Abuse)
        print("\n[Step 6] Executing GenAI & Agent Tool Security Engine...")
        ai_findings = await self.ai_security_engine.run_ai_security_scan()
        print(f"  [-] Verified GenAI & Agent Tool Findings: {len(ai_findings)}")
        all_findings.extend(ai_findings)

        print("\n================================================================")
        print("[+] FINAL UNIFIED SECURITY REPORT")
        print("================================================================")
        for finding in all_findings:
            print(f"\n[FINDING ID: {finding.finding_id}]")
            print(f"Title: {finding.title}")
            print(f"Category: {finding.vulnerability_type} | Severity: {finding.severity.value.upper()} | Status: {finding.status.value.upper()}")
            print(f"Affected Endpoint: {finding.affected_endpoint}")
            print(f"Reproduction Procedure:\n{finding.reproduction_procedure}")
            print(f"Remediation:\n{finding.remediation}")
        print("================================================================")
        return all_findings

if __name__ == "__main__":
    vulnshop_code = os.path.abspath("benchmarks/fixtures/vulnshop/app/main.py")
    pipeline = VibeGuardPipeline(
        target_code_path=vulnshop_code,
        target_base_url="http://127.0.0.1:8000"
    )
    asyncio.run(pipeline.run_pipeline())
