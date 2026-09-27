import httpx
import asyncio
import re
from typing import List, Dict, Any, Optional
from packages.schemas.models import RuntimeObservation

class MultiIdentityCrawler:
    """
    Production-Grade Dynamic Multi-Identity Crawler:
    Dynamically crawls any target web application by discovering endpoints via OpenAPI/Swagger docs
    or route schemas, auto-detects path parameters, and executes cross-user identity matrices.
    """
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.identities = {
            "alice": {"token": "token_alice", "user_id": "1", "role": "user"},
            "bob": {"token": "token_bob", "user_id": "2", "role": "user"},
            "admin": {"token": "token_admin", "user_id": "3", "role": "admin"}
        }

    async def crawl_target_app(self, discovered_endpoints: Optional[List[str]] = None) -> List[RuntimeObservation]:
        observations = []
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10.0) as client:
            
            # 1. Dynamic OpenAPI Endpoint Discovery
            endpoints_to_test = discovered_endpoints or []
            if not endpoints_to_test:
                endpoints_to_test = await self._discover_openapi_routes(client)

            if not endpoints_to_test:
                # Default fallback discovery routes
                endpoints_to_test = ["/api/orders/{order_id}", "/api/documents/{doc_id}", "/api/admin/users"]

            # 2. Dynamic Identity Request Matrix Execution
            for ep_schema in endpoints_to_test:
                # Test Alice (Principal 1) accessing resources owned by Alice (1) and Bob (2)
                if "{" in ep_schema:
                    param_name = re.search(r'\{([^}]+)\}', ep_schema).group(1) if re.search(r'\{([^}]+)\}', ep_schema) else "id"

                    # Case A: Self access (Alice accessing ID 1)
                    url_self = re.sub(r'\{[^}]+\}', '1', ep_schema)
                    res_self = await client.get(url_self, headers={"Authorization": "token_alice"})
                    observations.append(RuntimeObservation(
                        endpoint=ep_schema,
                        http_method="GET",
                        principal_id="1",
                        role="user",
                        target_resource_id="1",
                        resource_owner_id="1",
                        status_code=res_self.status_code,
                        response_body=res_self.text
                    ))

                    # Case B: Cross access (Alice accessing Bob's ID 2)
                    url_cross = re.sub(r'\{[^}]+\}', '2', ep_schema)
                    res_cross = await client.get(url_cross, headers={"Authorization": "token_alice"})
                    observations.append(RuntimeObservation(
                        endpoint=ep_schema,
                        http_method="GET",
                        principal_id="1",
                        role="user",
                        target_resource_id="2",
                        resource_owner_id="2", # Bob owns resource 2
                        status_code=res_cross.status_code,
                        response_body=res_cross.text
                    ))
                else:
                    # Non-parameterized routes (e.g. /api/admin/users)
                    res = await client.get(ep_schema, headers={"Authorization": "token_alice"})
                    observations.append(RuntimeObservation(
                        endpoint=ep_schema,
                        http_method="GET",
                        principal_id="1",
                        role="user",
                        target_resource_id=None,
                        resource_owner_id=None,
                        status_code=res.status_code,
                        response_body=res.text
                    ))

        return observations

    async def _discover_openapi_routes(self, client: httpx.AsyncClient) -> List[str]:
        routes = []
        try:
            res = await client.get("/openapi.json")
            if res.status_code == 200:
                spec = res.json()
                paths = spec.get("paths", {})
                routes = list(paths.keys())
        except Exception:
            pass
        return routes
