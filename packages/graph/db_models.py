from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import declarative_base, relationship
import datetime
import uuid

Base = declarative_base()

def generate_uuid():
    return str(uuid.uuid4())

class DBApplication(Base):
    __tablename__ = "applications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    framework = Column(String(100), nullable=True)
    repo_url = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scans = relationship("DBScan", back_populates="application")

class DBScan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    application_id = Column(String(36), ForeignKey("applications.id"), nullable=False)
    status = Column(String(50), default="PENDING")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    application = relationship("DBApplication", back_populates="scans")
    findings = relationship("DBFinding", back_populates="scan")

class DBAuthorizationIntent(Base):
    __tablename__ = "authorization_intents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    endpoint = Column(String(255), nullable=False)
    http_method = Column(String(10), nullable=False)
    resource = Column(String(100), nullable=False)
    action = Column(String(50), nullable=False)
    auth_level = Column(String(50), nullable=False)
    ownership_required = Column(Boolean, default=False)
    evidence_json = Column(JSON, nullable=True)

class DBRuntimeObservation(Base):
    __tablename__ = "runtime_observations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    endpoint = Column(String(255), nullable=False)
    principal_id = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False)
    target_resource_id = Column(String(100), nullable=True)
    resource_owner_id = Column(String(100), nullable=True)
    status_code = Column(Integer, nullable=False)

class DBGraphNode(Base):
    __tablename__ = "graph_nodes"

    id = Column(String(255), primary_key=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    node_type = Column(String(100), nullable=False)
    attributes_json = Column(JSON, nullable=True)

class DBGraphEdge(Base):
    __tablename__ = "graph_edges"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    source_id = Column(String(255), nullable=False)
    target_id = Column(String(255), nullable=False)
    relationship = Column(String(100), nullable=False)

class DBFinding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(Float, default=1.0)
    status = Column(String(50), default="VERIFIED")
    affected_endpoint = Column(String(255), nullable=False)
    affected_resource = Column(String(255), nullable=False)
    reproduction_procedure = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    evidence_json = Column(JSON, nullable=True)

    scan = relationship("DBScan", back_populates="findings")

class DBExperiment(Base):
    __tablename__ = "experiments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    baseline_variant = Column(String(100), nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    false_positive_rate = Column(Float, nullable=False)
    raw_results_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
