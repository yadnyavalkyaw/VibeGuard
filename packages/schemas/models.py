from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import uuid

class ActionType(str, Enum):
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    EXECUTE = "EXECUTE"
    ADMIN = "ADMIN"

class AuthLevel(str, Enum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    ADMIN = "admin"
    STAFF = "staff"
    UNKNOWN = "unknown"

class VerificationStatus(str, Enum):
    POTENTIAL = "potential"
    SUSPICIOUS = "suspicious"
    CONFIRMED = "confirmed"
    VERIFIED = "verified"
    REJECTED = "rejected"

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# --- Authorization Intent Models ---
class OwnershipRequirement(BaseModel):
    required: bool = False
    field: Optional[str] = None           # e.g., "user_id"
    principal_field: Optional[str] = None # e.g., "user.id"

class CodeEvidence(BaseModel):
    file: str
    line: int
    snippet: Optional[str] = None

class AuthorizationIntent(BaseModel):
    id: str = Field(default_factory=lambda: f"INTENT-{uuid.uuid4().hex[:8]}")
    endpoint: str                      # e.g., "GET /api/orders/{id}"
    http_method: str                   # e.g., "GET"
    resource: str                      # e.g., "Order"
    action: ActionType                 # e.g., ActionType.READ
    auth_level: AuthLevel              # e.g., AuthLevel.AUTHENTICATED
    ownership: OwnershipRequirement
    evidence: List[CodeEvidence] = []

# --- Runtime Observation Models ---
class RuntimeObservation(BaseModel):
    id: str = Field(default_factory=lambda: f"OBS-{uuid.uuid4().hex[:8]}")
    endpoint: str
    http_method: str
    principal_id: str                  # e.g., "alice", "bob", "anon"
    role: str                          # e.g., "user", "admin"
    target_resource_id: Optional[str] = None # e.g., "1" (Alice's order), "2" (Bob's order)
    resource_owner_id: Optional[str] = None  # e.g., "2" (Bob)
    status_code: int
    headers: Dict[str, str] = {}
    response_body: Optional[str] = None
    response_hash: Optional[str] = None

# --- Contradiction & Finding Models ---
class Contradiction(BaseModel):
    id: str = Field(default_factory=lambda: f"CONTRA-{uuid.uuid4().hex[:8]}")
    intent_id: str
    observation_id: str
    principal_id: str
    target_resource_id: str
    resource_owner_id: str
    rule_violated: str
    description: str

class EvidenceItem(BaseModel):
    evidence_id: str = Field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:8]}")
    finding_id: str
    source_code: List[CodeEvidence] = []
    requests: List[Dict[str, Any]] = []
    responses: List[Dict[str, Any]] = []
    runtime_trace: List[str] = []
    observations: List[str] = []

class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8]}")
    title: str
    vulnerability_type: str            # e.g. "BOLA / IDOR", "SQLi", "Prompt Injection"
    severity: Severity
    confidence: float                  # 0.0 to 1.0
    status: VerificationStatus
    affected_endpoint: str
    affected_resource: str
    reproduction_procedure: str
    remediation: str
    evidence: Optional[EvidenceItem] = None
