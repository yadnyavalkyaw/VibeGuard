from typing import Dict, List, Set, Optional, Tuple
from packages.schemas.models import (
    AuthorizationIntent,
    RuntimeObservation,
    Contradiction,
    Finding,
    Severity,
    VerificationStatus,
    EvidenceItem,
    CodeEvidence
)

class GraphNode:
    def __init__(self, node_id: str, node_type: str, attributes: Optional[Dict] = None):
        self.id = node_id
        self.type = node_type
        self.attributes = attributes or {}

    def __repr__(self):
        return f"Node({self.type}:{self.id})"

class GraphEdge:
    def __init__(self, source_id: str, target_id: str, relationship: str, attributes: Optional[Dict] = None):
        self.source_id = source_id
        self.target_id = target_id
        self.relationship = relationship
        self.attributes = attributes or {}

    def __repr__(self):
        return f"Edge({self.source_id} -[{self.relationship}]-> {self.target_id})"

class AIAGraph:
    """
    Authorization-Intent Attack Graph (AIAG) representation and Contradiction Engine.
    """
    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self.intents: Dict[str, AuthorizationIntent] = {}
        self.observations: Dict[str, RuntimeObservation] = {}
        self.contradictions: List[Contradiction] = []

    def add_node(self, node_id: str, node_type: str, attributes: Optional[Dict] = None) -> GraphNode:
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(node_id, node_type, attributes)
        return self.nodes[node_id]

    def add_edge(self, source_id: str, target_id: str, relationship: str, attributes: Optional[Dict] = None):
        edge = GraphEdge(source_id, target_id, relationship, attributes)
        self.edges.append(edge)

    def add_authorization_intent(self, intent: AuthorizationIntent):
        self.intents[intent.endpoint] = intent
        
        # Add graph nodes
        ep_node = self.add_node(intent.endpoint, "Endpoint", {"method": intent.http_method})
        res_node = self.add_node(intent.resource, "Resource", {})
        act_node = self.add_node(f"{intent.http_method}_{intent.resource}", "Action", {"type": intent.action})
        req_node = self.add_node(f"REQ_{intent.endpoint}", "AuthorizationRequirement", {
            "auth_level": intent.auth_level,
            "ownership_required": intent.ownership.required,
            "owner_field": intent.ownership.field
        })

        # Connect edges
        self.add_edge(ep_node.id, act_node.id, "PERFORMS")
        self.add_edge(act_node.id, res_node.id, "TARGETS")
        self.add_edge(ep_node.id, req_node.id, "REQUIRES")

    def add_runtime_observation(self, obs: RuntimeObservation):
        self.observations[obs.id] = obs
        
        # Add nodes
        p_node = self.add_node(obs.principal_id, "Principal", {"role": obs.role})
        obs_node = self.add_node(obs.id, "RuntimeObservation", {
            "status_code": obs.status_code,
            "endpoint": obs.endpoint
        })
        
        self.add_edge(obs_node.id, obs.endpoint, "OBSERVES")

        if obs.target_resource_id:
            res_inst_id = f"RES_{obs.target_resource_id}"
            res_inst_node = self.add_node(res_inst_id, "ResourceInstance", {
                "owner_id": obs.resource_owner_id
            })
            self.add_edge(obs_node.id, res_inst_node.id, "ACCESSES")

            if obs.resource_owner_id:
                owner_node = self.add_node(obs.resource_owner_id, "Principal", {})
                self.add_edge(res_inst_node.id, owner_node.id, "OWNED_BY")

    def evaluate_contradictions(self) -> List[Contradiction]:
        """
        Deterministic Contradiction Engine Theorem:
        ExpectedAccess(P, R) = FALSE  AND  ObservedAccess(P, R) = TRUE
        ==> Contradiction(P, R) = TRUE
        """
        detected_contradictions = []

        for obs_id, obs in self.observations.items():
            intent = self.intents.get(obs.endpoint)
            if not intent:
                continue

            # Check 1: BOLA / Ownership Check Contradiction
            if intent.ownership.required and obs.target_resource_id and obs.resource_owner_id:
                # Expected access is TRUE if principal is the owner or an admin
                expected_access = (str(obs.principal_id) == str(obs.resource_owner_id)) or (obs.role == "admin")
                observed_access = (200 <= obs.status_code < 300)

                if not expected_access and observed_access:
                    contra = Contradiction(
                        intent_id=intent.endpoint,
                        observation_id=obs.id,
                        principal_id=obs.principal_id,
                        target_resource_id=obs.target_resource_id,
                        resource_owner_id=obs.resource_owner_id,
                        rule_violated="BOLA_OWNERSHIP_CONTRADICTION",
                        description=(
                            f"BOLA Vulnerability Detected on {obs.endpoint}: "
                            f"Principal '{obs.principal_id}' successfully accessed Resource '{obs.target_resource_id}' "
                            f"owned by Principal '{obs.resource_owner_id}' despite static ownership restriction."
                        )
                    )
                    detected_contradictions.append(contra)

                    # Add graph node & edges for contradiction
                    contra_node = self.add_node(contra.id, "Contradiction", {"rule": contra.rule_violated})
                    req_node_id = f"REQ_{intent.endpoint}"
                    self.add_edge(obs.id, contra_node.id, "PRODUCES")
                    self.add_edge(contra_node.id, req_node_id, "CONTRADICTS")

            # Check 2: BFLA / Admin Role Check Contradiction
            if intent.auth_level == "admin" and obs.role != "admin":
                observed_access = (200 <= obs.status_code < 300)
                if observed_access:
                    contra = Contradiction(
                        intent_id=intent.id,
                        observation_id=obs.id,
                        principal_id=obs.principal_id,
                        target_resource_id="N/A",
                        resource_owner_id="N/A",
                        rule_violated="BFLA_ROLE_CONTRADICTION",
                        description=(
                            f"BFLA Vulnerability Detected on {obs.endpoint}: "
                            f"Non-admin principal '{obs.principal_id}' (role: '{obs.role}') "
                            f"successfully executed restricted admin endpoint."
                        )
                    )
                    detected_contradictions.append(contra)

        self.contradictions = detected_contradictions
        return detected_contradictions
