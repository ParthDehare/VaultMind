import os
from supabase import create_client, Client
import redis
from core.secrets_config import secrets

# ==========================================
# 1. SUPABASE CONNECTION (For Audit & Evidence)
# ==========================================
SUPABASE_URL = secrets.get("SUPABASE_URL")
SUPABASE_KEY = secrets.get("SUPABASE_KEY")

def get_supabase_client():
    if SUPABASE_URL and SUPABASE_KEY:
        try:
            supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
            print("[DB] Supabase Connected Successfully!")
            return supabase
        except Exception as e:
            print(f"[DB] Supabase Error: {e}")
            return None
    else:
        print("[DB] Supabase credentials missing or placeholder in .env. Skipping DB.")
        return None

def get_tenant_supabase_client(tenant_id: str = "default_tenant"):
    """
    Returns a Supabase client context scoped by tenant_id for Row-Level Security (RLS).
    Sets the x-tenant-id postgrest header so Supabase PostgreSQL RLS policies evaluate correctly.
    """
    client = get_supabase_client()
    if client and hasattr(client, "postgrest") and hasattr(client.postgrest, "session"):
        try:
            client.postgrest.session.headers.update({"x-tenant-id": str(tenant_id)})
        except Exception as e:
            print(f"[DB] Could not set RLS x-tenant-id header: {e}")
    return client

# ==========================================
# 2. REDIS CONNECTION (For Live Scores)
# ==========================================
REDIS_HOST = secrets.get("REDIS_HOST", "localhost")
REDIS_PORT = secrets.get_int("REDIS_PORT", 6379)

def get_redis_client():
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping() # Connection test
        print("[DB] Redis Connected Successfully!")
        return r
    except Exception as e:
        print(f"[DB] Redis not running (using fallback memory): {e}")
        return None

# Initialize clients
supabase_db = get_supabase_client()
redis_db = get_redis_client()
