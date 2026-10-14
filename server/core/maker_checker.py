from fastapi import HTTPException, status
from core.db_connections import redis_db
from core.notifier import send_fraud_alert
import asyncio
from fastapi import BackgroundTasks

# Memory fallback in case Redis is not available
_memory_cache = {}

def cache_maker_ip(transaction_id: str, ip_address: str):
    """
    Caches the IP address of the Maker who initiated a high-value transaction.
    The lock expires after 24 hours (86400 seconds) to prevent memory leaks.
    """
    redis_key = f"maker_ip:{transaction_id}"
    if redis_db:
        redis_db.setex(redis_key, 86400, ip_address)
    else:
        _memory_cache[redis_key] = ip_address


def verify_checker_ip(transaction_id: str, checker_ip: str, transaction_payload: dict = None, background_tasks: BackgroundTasks = None):
    """
    Verifies that the Checker approving the transaction is not using the same physical machine
    (IP address) as the Maker who initiated it.

    Raises:
        HTTPException 403 Forbidden if collision is detected.
    """
    redis_key = f"maker_ip:{transaction_id}"

    if redis_db:
        maker_ip = redis_db.get(redis_key)
    else:
        maker_ip = _memory_cache.get(redis_key)

    if maker_ip and maker_ip == checker_ip:
        # IP Collision detected! Maker and Checker are on the same machine.

        # Trigger critical red flag alert if background tasks and payload are provided
        if background_tasks and transaction_payload:
            background_tasks.add_task(send_fraud_alert, transaction_payload, 100)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MAKER-CHECKER COLLISION DETECTED: Approval blocked. "
                   "Initiator and Approver cannot share the same physical IP address."
        )

    return True

def clear_maker_ip(transaction_id: str):
    """Cleanup after successful approval or rejection"""
    redis_key = f"maker_ip:{transaction_id}"
    if redis_db:
        redis_db.delete(redis_key)
    else:
        _memory_cache.pop(redis_key, None)
