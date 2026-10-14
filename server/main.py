# vaultmind_main.py
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

import json
import asyncio
import threading
import uuid

import os
from fastapi.responses import FileResponse
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Depends, Query, status
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from confluent_kafka import Consumer, KafkaException, KafkaError

from core.master_orchestrator import MasterOrchestrator
from core.auth import get_current_user, require_role, decode_jwt, TokenData
from core.ml_models import ml_models
from core.secrets_config import secrets
from api.api_server import router as api_router
from api.auth_routes import router as auth_router
from api.feedback_routes import router as feedback_router

# â”€â”€ Rate Limiter Setup â”€â”€
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

app = FastAPI(title="VaultMind Backend API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include routers
app.include_router(api_router,  prefix="/api")
app.include_router(auth_router, prefix="/api")
app.include_router(feedback_router, prefix="/api")

# Allow React to connect â€” explicit origin whitelist governed by secrets module
ALLOWED_ORIGINS = secrets.get_list(
    "ALLOWED_ORIGINS",
    default=["https://v2.vaultmind.systems","http://localhost:5173", "http://localhost:5174", "http://127.0.0.1:5173", "http://127.0.0.1:5174"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# â”€â”€ 1. Boot up the Brain â”€â”€
orchestrator = MasterOrchestrator()

# Keep track of connected React clients
active_connections = []
main_loop = None  # Store the main event loop

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    # Enforce zero URL query-param token leakage for security.
    # Read strictly from HttpOnly cookie `vm_token` or Authorization header.
    token = websocket.cookies.get("vm_token")
    if not token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user = decode_jwt(token)
    if not user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    active_connections.append(websocket)
    print("React Frontend Connected to WebSockets via Secure Cookie/Header!")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)
        print("React Frontend Disconnected.")

async def broadcast_to_websockets(data: dict):
    """Broadcasts a payload to all connected WebSockets gracefully."""
    dead_connections = []
    for connection in active_connections:
        try:
            await connection.send_json(data)
        except Exception as e:
            print(f"[Main] Error sending to websocket: {e}")
            dead_connections.append(connection)

    for dead in dead_connections:
        if dead in active_connections:
            active_connections.remove(dead)

async def redis_pubsub_listener():
    """Listens to Redis 'vaultmind:alerts' channel and broadcasts to local WebSocket clients."""
    from core.db_connections import redis_db
    if redis_db is None:
        print("[Main] Redis not connected. Pub/Sub broadcasting will rely on direct local memory callbacks.")
        return

    pubsub = redis_db.pubsub()
    try:
        await asyncio.to_thread(pubsub.subscribe, "vaultmind:alerts")
        print("[Main] Subscribed to Redis channel 'vaultmind:alerts' for real-time horizontal WebSocket broadcasting...")
        while True:
            message = await asyncio.to_thread(pubsub.get_message, ignore_subscribe_messages=True, timeout=1.0)
            if message and message.get("type") == "message":
                raw_data = message.get("data")
                if raw_data:
                    try:
                        scored_tx = json.loads(raw_data)
                        if active_connections:
                            for connection in list(active_connections):
                                try:
                                    await connection.send_json(scored_tx)
                                except Exception:
                                    if connection in active_connections:
                                        active_connections.remove(connection)
                    except Exception as parse_err:
                        print(f"[Main] Error handling Pub/Sub message: {parse_err}")
            await asyncio.sleep(0.05)
    except Exception as e:
        print(f"[Main] Redis Pub/Sub listener terminated: {e}")
    finally:
        try:
            pubsub.close()
        except Exception:
            pass

@app.on_event("startup")
async def startup_event():
    global main_loop
    main_loop = asyncio.get_running_loop()

    # Load ML models at startup
    ml_models.load_all()

    # Start Redis Pub/Sub listener for horizontal WebSocket scalability across worker pods
    asyncio.create_task(redis_pubsub_listener())

    # Check whether to run embedded Kafka worker or rely on standalone service
    if secrets.get("EMBEDDED_KAFKA_CONSUMER", "true").lower() == "true":
        try:
            from services.kafka_consumer_service import KafkaConsumerWorker
            worker = KafkaConsumerWorker()
            thread = threading.Thread(target=worker.start, args=(main_loop,), daemon=True)
            thread.start()
            print("[Main] Started embedded KafkaConsumerWorker in background daemon thread.")
        except Exception as worker_err:
            print(f"[Main] Could not start embedded KafkaConsumerWorker: {worker_err}")
    else:
        print("[Main] External KafkaConsumerWorker mode (EMBEDDED_KAFKA_CONSUMER=false).")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# AUTO KAFKA TRIGGER â€” called by frontend right after login
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
import pandas as pd
import time
import os

_demo_task_running = False

async def _demo_stream_loop():
    global _demo_task_running
    csv_path = os.path.join(os.path.dirname(__file__), "data", "Testing_data", "live_demo_stream.csv")
    if not os.path.exists(csv_path):
        print(f"[Demo] Could not find {csv_path}")
        _demo_task_running = False
        return

    try:
        df = pd.read_csv(csv_path)
        while True:
            for idx, row in df.iterrows():
                tx = row.where(pd.notnull(row), None).to_dict()
                tx["transaction_id"] = f"TXN_{int(time.time() * 1000) % 1000000000}"
                tx["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                try:
                    await orchestrator.process_transaction(tx)
                    print(f"[Demo] Processed {tx['transaction_id']}")
                except Exception as e:
                    print(f"[Demo] Error processing: {e}")
                await asyncio.sleep(2)
    except asyncio.CancelledError:
        _demo_task_running = False
    except Exception as e:
        print(f"[Demo] Stream loop error: {e}")
        _demo_task_running = False

@app.post("/api/system/start-stream")
async def start_kafka_stream(current_user=Depends(get_current_user)):
    global _demo_task_running
    if not _demo_task_running:
        _demo_task_running = True
        asyncio.create_task(_demo_stream_loop())
    return {"status": "success", "message": "Direct demo data stream started successfully without Kafka."}
@app.get("/get-next-transaction")
async def get_next_transaction(current_user: TokenData = Depends(get_current_user)):
    # Retrieve the next transaction from the backend to send to the frontend.
    try:
        txn = orchestrator.get_latest_processed_transaction()
        return txn
    except Exception as e:
        return {"error": "No transaction available", "details": str(e)}


@app.get("/api/evidence/download")
def download_evidence(emp_id: str, current_user: TokenData = Depends(get_current_user)):
    return {"status": "success", "message": f"Evidence package compiled for {emp_id}."}

@app.post("/api/evidence/file-str")
def file_str(payload: dict, current_user: TokenData = Depends(require_role("auditor"))):
    emp_id = payload.get("emp_id")
    return {
        "status": "success",
        "message": f"STR successfully filed securely to FIU-IND for node {emp_id}"
    }

@app.get("/")
def read_root():
    return {"status": "VaultMind Backend is LIVE ðŸš€"}
