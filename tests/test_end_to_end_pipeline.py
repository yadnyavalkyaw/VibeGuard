import pytest
import asyncio
import os
import threading
import time
import uvicorn
from benchmarks.fixtures.vulnshop.app.main import app
from services.orchestrator.pipeline import VibeGuardPipeline

def run_test_server():
    uvicorn.run(app, host="127.0.0.1", port=8005, log_level="warning")

@pytest.fixture(scope="module", autouse=True)
def setup_server():
    server_thread = threading.Thread(target=run_test_server, daemon=True)
    server_thread.start()
    time.sleep(1.5) # Wait for server to start
    yield

def test_vibeguard_end_to_end_bola_detection():
    async def _run():
        vulnshop_code = os.path.abspath("benchmarks/fixtures/vulnshop/app/main.py")
        pipeline = VibeGuardPipeline(
            target_code_path=vulnshop_code,
            target_base_url="http://127.0.0.1:8005"
        )
        findings = await pipeline.run_pipeline()
        
        assert len(findings) >= 1
        bola_finding = next((f for f in findings if f.vulnerability_type == "BOLA / IDOR"), None)
        assert bola_finding is not None
        assert bola_finding.status.value == "verified"
        assert bola_finding.confidence == 1.0

    asyncio.run(_run())
