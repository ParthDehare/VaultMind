"""
VaultMind 2.0 - Persistence Layer (Models)
Defines the WORM (Write Once Read Many) compatible database schema
for storing fraud alerts, audit logs, and multi-tenant organizations securely using SQLAlchemy.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float
from sqlalchemy.orm import declarative_base

# Base declarative class for SQLAlchemy models
Base = declarative_base()


class Tenant(Base):
    """
    Tenant Model
    Represents an enterprise organization, bank branch cluster, or isolated agency unit
    with strict multi-tenant Row-Level Security (RLS) isolation.
    """
    __tablename__ = 'tenants'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class FraudAlert(Base):
    """
    FraudAlert Model
    Represents an immutable, tamper-evident record of a detected anomaly.
    Uses cryptographic hashes to link records in a blockchain-like structure.
    Includes multi-tenant isolation (`tenant_id`).
    """
    __tablename__ = 'alerts'

    # 1. Core Fields
    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=False, default="default_tenant", index=True)
    transaction_id = Column(String(255), nullable=False, index=True)
    emp_id = Column(String(255), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    action_type = Column(String(255), nullable=False)
    detection_reasons = Column(Text, nullable=True)

    # 2. Cryptographic Ledger Fields
    block_id = Column(Integer, nullable=False, unique=True)
    data_hash_sha256 = Column(String(64), nullable=False)
    block_hash_sha256 = Column(String(64), nullable=False)
    previous_hash = Column(String(64), nullable=False)

    # 3. Compliance & Audit Fields
    auditor_status = Column(String(50), default="PENDING", nullable=False)
    is_tampered = Column(Boolean, default=False, nullable=False)
    retention_expiry_date = Column(DateTime, nullable=False)


class EvidenceLogORM(Base):
    """
    EvidenceLog ORM Model
    Matches the Supabase `evidence_logs` table schema with Row-Level Security (`tenant_id`) indexing.
    """
    __tablename__ = 'evidence_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=False, default="default_tenant", index=True)
    transaction_id = Column(String(255), nullable=False, index=True)
    employee_id = Column(String(255), nullable=False, index=True)
    cbsi_score = Column(Float, nullable=False)
    risk_level = Column(String(50), nullable=False)
    evidence_path = Column(String(500), nullable=False)
    agent_flags = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ModelRetrainingQueue(Base):
    """
    ModelRetrainingQueue ORM Model
    Captures analyst active-learning feedback (CONFIRM vs FALSE_ALARM) on specific alerts
    to feed into batch recalibration queues (`train_agent1.py`, `train_agent2.py`).
    """
    __tablename__ = 'model_retraining_queue'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), nullable=False, default="default_tenant", index=True)
    alert_id = Column(String(255), nullable=False, index=True)
    employee_id = Column(String(255), nullable=False, index=True)
    feedback_action = Column(String(50), nullable=False)  # "CONFIRM" or "FALSE_ALARM"
    analyst_remarks = Column(Text, nullable=True)
    original_score = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_processed = Column(Boolean, default=False, nullable=False)
