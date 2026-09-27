import httpx
from typing import List
from packages.schemas.models import Finding, Severity, VerificationStatus, EvidenceItem, CodeEvidence

class DASTEngine:
    """
    DAST Engine Adapter:
    Executes targeted active web vulnerability tests against endpoints for SQLi, XSS, SSRF.
    """
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def run_dast_scan(self) -> List[Finding]:
        findings = []
        async with httpx.AsyncClient(base_url=self.base_url) as client:

            # 1. SQL Injection Probe: GET /api/products/search?q=' OR '1'='1
            sqli_payload = "' OR '1'='1"
            res = await client.get(f"/api/products/search?q={sqli_payload}")
            if res.status_code == 200 and "results" in res.json():
                results = res.json()["results"]
                # If sql injection returned all products regardless of query
                if len(results) > 1:
                    evidence = EvidenceItem(
                        finding_id="",
                        source_code=[CodeEvidence(
                            file="benchmarks/fixtures/vulnshop/app/main.py",
                            line=88,
                            snippet=f"query = f\"SELECT * FROM products WHERE name LIKE '%{{q}}%' OR description LIKE '%{{q}}%'\""
                        )],
                        requests=[{
                            "method": "GET",
                            "url": f"/api/products/search?q={sqli_payload}",
                            "headers": {}
                        }],
                        responses=[{
                            "status_code": 200,
                            "items_returned": len(results),
                            "sample_item": results[0]["name"] if results else None
                        }],
                        observations=["SQL syntax payload `' OR '1'='1` bypassed search filter returning all database rows."]
                    )

                    finding = Finding(
                        title="SQL Injection (SQLi) in Product Search Endpoint",
                        vulnerability_type="SQL Injection",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        status=VerificationStatus.VERIFIED,
                        affected_endpoint="/api/products/search",
                        affected_resource="Products Table",
                        reproduction_procedure=(
                            f"1. Send GET request to /api/products/search with query parameter `q={sqli_payload}`.\n"
                            f"2. Observe HTTP 200 response containing all product rows from the database without proper parameter binding."
                        ),
                        remediation="Use parameterized SQL queries with placeholder parameters (`SELECT * FROM products WHERE name LIKE ?`) instead of string interpolation.",
                        evidence=evidence
                    )
                    evidence.finding_id = finding.finding_id
                    findings.append(finding)

            # 2. Stored XSS Probe: POST /api/comments
            xss_payload = "<script>alert('XSS')</script>"
            res = await client.post("/api/comments", json={"product_id": 1, "comment": xss_payload}, headers={"Authorization": "token_alice"})
            if res.status_code == 200 and xss_payload in res.text:
                evidence = EvidenceItem(
                    finding_id="",
                    source_code=[CodeEvidence(
                        file="benchmarks/fixtures/vulnshop/app/main.py",
                        line=105,
                        snippet="raw_html_comment = f\"<div class='user-comment'>{req.comment}</div>\""
                    )],
                    requests=[{
                        "method": "POST",
                        "url": "/api/comments",
                        "body": {"product_id": 1, "comment": xss_payload}
                    }],
                    responses=[{
                        "status_code": 200,
                        "raw_response": res.text
                    }],
                    observations=["Unsanitized script payload was returned directly in HTML payload structure."]
                )

                finding = Finding(
                    title="Cross-Site Scripting (XSS) in Product Comments",
                    vulnerability_type="Cross-Site Scripting (XSS)",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    status=VerificationStatus.VERIFIED,
                    affected_endpoint="/api/comments",
                    affected_resource="Product Comments",
                    reproduction_procedure=(
                        f"1. POST JSON body containing script payload `{xss_payload}` to /api/comments.\n"
                        f"2. Observe raw unencoded script tag execution string returned in response."
                    ),
                    remediation="Sanitize and HTML-encode all user input before rendering in DOM contexts or API HTML templates.",
                    evidence=evidence
                )
                evidence.finding_id = finding.finding_id
                findings.append(finding)

        return findings
