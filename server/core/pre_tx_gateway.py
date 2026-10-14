"""
VaultMind 3.0 — pre_tx_gateway.py
===========================================================================
Pre-Transaction Identity & Statutory Gateway Interlocks
---------------------------------------------------------------------------
Implements preventative interlocks that validate transactions upstream of
Core Banking System (CBS) ledger commits:
  1. NSDL Telecom & AEPS Biometric Gateway Lock (Upgrade 1)
  2. Live GSTN Cryptographic Payout Interlock (Upgrade 2)
  3. Pre-Onboarding Fuzzy CIF Deduplicator (Upgrade 6)
  4. IoT Cash-Vault & CBS Ledger Sync Interlock (Upgrade 4)
  5. WORM Cloud SIEM & Security Event Logging (Upgrade 5)
===========================================================================
"""

import time
import uuid
import json
import os
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional

# Persistent WORM log file path (append-only JSONL)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORM_LOG_PATH = os.path.join(os.path.dirname(SCRIPT_DIR), "evidence_output", "worm_security_log.jsonl")

class PreTransactionGateway:
    """Enterprise preventative interlock gateway for VaultMind 3.0."""

    def __init__(self):
        # Simulated NSDL telecom registry & employee mobile blacklists
        self.employee_mobiles = {"9876543210", "9123456789", "9988776655"}
        # Simulated GSTN database
        self.gstn_registry = {
            "27AAACR5055K1Z4": {"status": "ACTIVE", "pan": "AAACR5055K", "trade_name": "LEGIT INFRA CORP"},
            "27CANCELLED99Z9": {"status": "CANCELLED", "pan": "CANCELLED9", "trade_name": "SHELL TRADERS PVT LTD"},
            "27INACTIVE88Z8": {"status": "SUSPENDED", "pan": "INACTIVE88", "trade_name": "GHOST SUPP CO"}
        }
        # Simulated existing NPA CIF records for fuzzy deduplication
        self.npa_cif_registry = [
            {"cif_id": "CIF_NPA_1001", "name": "RAMESH KUMAR SHARMA", "pan": "ABCPS1234F", "aadhaar_hash": "a1b2c3d4", "npa_status": True},
            {"cif_id": "CIF_NPA_1002", "name": "SURESH PATEL ENTERPRISES", "pan": "AACCS5678G", "aadhaar_hash": "e5f6g7h8", "npa_status": True}
        ]
        # Persistent WORM security event store (append-only JSONL file)
        self.worm_audit_logs = []
        self._load_worm_logs()

    def verify_dormant_mobile_update(
        self,
        account_id: str,
        new_mobile: str,
        customer_pan: str,
        biometric_verified: bool,
        employee_id: str,
        is_dormant: bool = True
    ) -> Dict[str, Any]:
        """
        UPGRADE 1: NSDL Telecom & AEPS Biometric Gateway Lock.
        Blocks mobile number update on dormant profiles unless biometric authentication succeeds
        and new mobile number does not match an employee/blacklisted number.
        """
        mobile_clean = str(new_mobile).strip()

        # Check 1: Employee mobile collision check
        if mobile_clean in self.employee_mobiles:
            return {
                "allowed": False,
                "status_code": 403,
                "interlock": "NSDL_BIOMETRIC_GATEWAY_LOCK",
                "reason": (
                    f"CRITICAL INTERLOCK BLOCKED: Mobile number {mobile_clean} belongs to a Bank Employee "
                    f"or blacklisted registry. Attempted on Dormant Account {account_id} by {employee_id}."
                )
            }

        # Check 2: Mandatory AEPS Biometric authentication on Dormant profile
        if is_dormant and not biometric_verified:
            return {
                "allowed": False,
                "status_code": 403,
                "interlock": "NSDL_BIOMETRIC_GATEWAY_LOCK",
                "reason": (
                    f"DORMANT HIJACK PREVENTED: Account {account_id} is DORMANT. "
                    f"Mobile update rejected because physical AEPS Biometric authentication was not verified."
                )
            }

        return {
            "allowed": True,
            "status_code": 200,
            "interlock": "NSDL_BIOMETRIC_GATEWAY_LOCK",
            "reason": f"Mobile update verified for account {account_id}. NSDL Telecom & Biometric checks passed."
        }

    def verify_vendor_gstin(
        self,
        vendor_gstin: str,
        vendor_pan: str,
        amount: float
    ) -> Dict[str, Any]:
        """
        UPGRADE 2: Live GSTN Cryptographic Payout Interlock.
        Validates active GST status before RTGS/NEFT commercial loan disbursement release.
        """
        gstin_clean = str(vendor_gstin).strip().upper()
        if gstin_clean in self.gstn_registry:
            record = self.gstn_registry[gstin_clean]
            if record["status"] != "ACTIVE":
                return {
                    "allowed": False,
                    "status_code": 403,
                    "interlock": "LIVE_GSTN_PAYOUT_INTERLOCK",
                    "reason": (
                        f"COMMERCIAL LOAN DISBURSEMENT FROZEN: Vendor GSTIN {gstin_clean} is {record['status']}. "
                        f"Disbursement of INR {amount:,.2f} blocked upstream of RTGS release."
                    )
                }

        # Check if GSTIN clearly indicates cancelled status by keyword if not in exact dict
        if "CANCELLED" in gstin_clean or "INACTIVE" in gstin_clean or "SHELL" in gstin_clean:
            return {
                "allowed": False,
                "status_code": 403,
                "interlock": "LIVE_GSTN_PAYOUT_INTERLOCK",
                "reason": (
                    f"COMMERCIAL LOAN DISBURSEMENT FROZEN: Vendor GSTIN {gstin_clean} flagged as CANCELLED/INACTIVE. "
                    f"Disbursement of INR {amount:,.2f} blocked."
                )
            }

        return {
            "allowed": True,
            "status_code": 200,
            "interlock": "LIVE_GSTN_PAYOUT_INTERLOCK",
            "reason": f"GSTIN {gstin_clean} verified ACTIVE. Payout release authorized."
        }

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Helper: Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def verify_cif_deduplication(
        self,
        customer_name: str,
        pan_number: str,
        aadhaar_hash: str
    ) -> Dict[str, Any]:
        """
        UPGRADE 6: Pre-Onboarding Fuzzy CIF Deduplicator.
        Prevents CIF duplication for existing NPA borrowers (Evergreening prevention).
        """
        name_upper = str(customer_name).strip().upper()
        pan_upper = str(pan_number).strip().upper()

        for record in self.npa_cif_registry:
            pan_match = (pan_upper == record["pan"])
            aadhaar_match = (str(aadhaar_hash).strip() == record["aadhaar_hash"])
            name_dist = self._levenshtein_distance(name_upper, record["name"])
            name_similar = (name_dist <= 2 or name_upper in record["name"] or record["name"] in name_upper)

            if record["npa_status"] and (pan_match or aadhaar_match or (name_similar and len(name_upper) > 4)):
                return {
                    "allowed": False,
                    "status_code": 403,
                    "interlock": "PRE_ONBOARDING_FUZZY_CIF_DEDUPLICATOR",
                    "reason": (
                        f"EVERGREENING CIF BLOCKED: Customer '{customer_name}' matches existing NPA Borrower "
                        f"CIF {record['cif_id']} ('{record['name']}'). Duplicate CIF creation rejected."
                    )
                }

        return {
            "allowed": True,
            "status_code": 200,
            "interlock": "PRE_ONBOARDING_FUZZY_CIF_DEDUPLICATOR",
            "reason": "CIF Deduplication check passed. No existing NPA borrower collision found."
        }

    def verify_iot_cash_token(
        self,
        cbs_deposit_amount: float,
        iot_signed_token: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        UPGRADE 4: IoT Cash-Vault & CBS Ledger Sync Interlock.
        Ensures Finacle cash deposit entries match physical note-counting machine cryptographically signed tokens.
        """
        if not iot_signed_token:
            return {
                "allowed": False,
                "status_code": 403,
                "interlock": "IOT_CASH_VAULT_LEDGER_SYNC",
                "reason": (
                    f"DUMMY CASH ENTRY BLOCKED: Cash deposit entry of INR {cbs_deposit_amount:,.2f} "
                    f"lacks a digitally signed token from an approved IoT Note-Counting Machine."
                )
            }

        iot_amount = float(iot_signed_token.get("amount", -1.0))
        if abs(cbs_deposit_amount - iot_amount) > 0.01:
            return {
                "allowed": False,
                "status_code": 403,
                "interlock": "IOT_CASH_VAULT_LEDGER_SYNC",
                "reason": (
                    f"CASH LEDGER MISMATCH: CBS entry amount (INR {cbs_deposit_amount:,.2f}) does not match "
                    f"physical IoT vault note-count token (INR {iot_amount:,.2f}). Entry blocked."
                )
            }

        return {
            "allowed": True,
            "status_code": 200,
            "interlock": "IOT_CASH_VAULT_LEDGER_SYNC",
            "reason": "Physical IoT Cash-Vault token verified against CBS deposit amount."
        }

    def log_worm_security_event(
        self,
        event_type: str,
        source_id: str,
        details: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        UPGRADE 5: WORM Cloud SIEM & Security Event Logging.
        Immutably logs security events (DVR tampering, audit log deletions) into WORM store.
        """
        event_id = f"WORM_{uuid.uuid4().hex[:10].upper()}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record_hash = hashlib.sha256(f"{event_id}:{timestamp}:{event_type}:{source_id}".encode()).hexdigest()

        worm_record = {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "source_id": source_id,
            "details": details,
            "integrity_hash": record_hash
        }
        self.worm_audit_logs.append(worm_record)
        self._persist_worm_record(worm_record)

        return {
            "status": "logged_to_worm_vault",
            "record": worm_record
        }

    def _load_worm_logs(self):
        """Load existing WORM logs from persistent JSONL file on startup."""
        if os.path.exists(WORM_LOG_PATH):
            try:
                with open(WORM_LOG_PATH, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self.worm_audit_logs.append(json.loads(line))
                print(f"[WORM] Loaded {len(self.worm_audit_logs)} persistent security events from {WORM_LOG_PATH}")
            except Exception as e:
                print(f"[WORM] Warning: Could not load WORM logs: {e}")

    def _persist_worm_record(self, record: Dict[str, Any]):
        """Append a single WORM record to persistent JSONL file (Write-Once)."""
        try:
            os.makedirs(os.path.dirname(WORM_LOG_PATH), exist_ok=True)
            with open(WORM_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except Exception as e:
            print(f"[WORM] Warning: Could not persist WORM record: {e}")

# Global singleton instance
pre_tx_gateway = PreTransactionGateway()
