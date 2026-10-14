# server/services/kafka_consumer_service.py
"""
VaultMind Decoupled Kafka Consumer Worker & DLQ Service
Can be run as an independent microservice (`python -m services.kafka_consumer_service`)
or embedded gracefully inside the FastAPI host during local development.
Features:
- Non-blocking async execution of the 8-agent MasterOrchestrator pipeline.
- Exponential backoff retry loop for transient database or model errors.
- Dead Letter Queue (DLQ) publishing (`live-transactions-dlq`) for unrecoverable or malformed payloads.
- Automatic Redis Pub/Sub broadcast (`vaultmind:alerts`) upon successful scoring.
"""
import os
import sys
import json
import uuid
import time
import asyncio
import logging
import threading
from datetime import datetime
from confluent_kafka import Consumer, Producer, KafkaException, KafkaError

from core.master_orchestrator import MasterOrchestrator
from core.secrets_config import secrets
from core.db_connections import redis_db

# Setup logging
logger = logging.getLogger("KafkaConsumerService")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class KafkaConsumerWorker:
    """Enterprise Kafka consumer worker decoupling ingestion from API serving threads."""

    def __init__(self, topic: str = "live-transactions", dlq_topic: str = "live-transactions-dlq"):
        self.topic = topic
        self.dlq_topic = dlq_topic
        self.broker = secrets.get("KAFKA_BROKER", "localhost:9092")
        self.group_id = secrets.get("KAFKA_GROUP_ID", f"vaultmind-worker-{uuid.uuid4()}")
        self.max_retries = secrets.get_int("KAFKA_MAX_RETRIES", 3)
        self.running = False
        self.orchestrator = MasterOrchestrator()

        # Initialize DLQ producer
        try:
            self.dlq_producer = Producer({"bootstrap.servers": self.broker})
            logger.info(f"[KafkaWorker] DLQ Producer ready pointing to broker: {self.broker}")
        except Exception as e:
            logger.error(f"[KafkaWorker] Could not initialize DLQ Producer: {e}")
            self.dlq_producer = None

    def _publish_to_dlq(self, raw_payload: str, error_msg: str, topic: str = "", partition: int = -1, offset: int = -1):
        """Send unrecoverable payloads to the Dead Letter Queue."""
        if not self.dlq_producer:
            logger.critical(f"[DLQ DROP] No DLQ producer. Dropped payload: {raw_payload[:100]}... Error: {error_msg}")
            return

        try:
            dlq_message = {
                "original_payload": raw_payload,
                "error": error_msg,
                "timestamp": datetime.utcnow().isoformat(),
                "original_topic": topic or self.topic,
                "original_partition": partition,
                "original_offset": offset,
                "worker_id": self.group_id
            }
            self.dlq_producer.produce(
                self.dlq_topic,
                value=json.dumps(dlq_message).encode("utf-8")
            )
            self.dlq_producer.flush(1.0)
            logger.warning(f"[DLQ] Successfully routed failed message to '{self.dlq_topic}'")
        except Exception as dlq_err:
            logger.critical(f"[DLQ FATAL] Failed to publish to DLQ '{self.dlq_topic}': {dlq_err}")

    async def _process_with_retries(self, tx: dict, raw_val: str, topic: str, partition: int, offset: int):
        """Execute transaction scoring with exponential backoff retry."""
        attempt = 0
        while attempt <= self.max_retries:
            try:
                # Score transaction via MasterOrchestrator
                scored_tx = await self.orchestrator.process_transaction(tx)

                # Publish to Redis Pub/Sub for cross-worker WebSocket broadcast
                if redis_db:
                    try:
                        redis_db.publish("vaultmind:alerts", json.dumps(scored_tx))
                    except Exception as redis_err:
                        logger.error(f"[KafkaWorker] Redis Pub/Sub broadcast failed: {redis_err}")

                return scored_tx
            except Exception as e:
                attempt += 1
                if attempt > self.max_retries:
                    logger.error(f"[KafkaWorker] Exhausted {self.max_retries} retries for TXN {tx.get('transaction_id')}. Routing to DLQ.")
                    self._publish_to_dlq(raw_val, str(e), topic, partition, offset)
                    return None
                backoff_time = 0.5 * (2 ** attempt)
                logger.warning(f"[KafkaWorker] Error scoring TXN {tx.get('transaction_id')}: {e}. Retrying in {backoff_time:.1f}s (Attempt {attempt}/{self.max_retries})...")
                await asyncio.sleep(backoff_time)

    def start(self, loop=None):
        """Start the synchronous consumer loop (designed to run inside a dedicated thread or process)."""
        self.running = True
        consumer_config = {
            "bootstrap.servers": self.broker,
            "group.id": self.group_id,
            "auto.offset.reset": "latest",
            "enable.auto.commit": True
        }

        try:
            consumer = Consumer(consumer_config)
            consumer.subscribe([self.topic])
            logger.info(f"[KafkaWorker] Consumer subscribed to topic '{self.topic}' (Group: {self.group_id})")
        except Exception as e:
            logger.error(f"[KafkaWorker] Failed to start Confluent Consumer: {e}")
            return

        # Ensure we have an event loop for async orchestrator calls
        if loop is None:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

        try:
            while self.running:
                msg = consumer.poll(1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error(f"[KafkaWorker] Consumer error: {msg.error()}")
                    continue

                raw_val = msg.value().decode("utf-8")
                try:
                    parsed_val = json.loads(raw_val)
                    tx = {k: v for k, v in parsed_val.items() if v is not None}
                except Exception as parse_err:
                    logger.error(f"[KafkaWorker] Malformed JSON: {parse_err}")
                    self._publish_to_dlq(raw_val, f"JSON Parse Error: {parse_err}", msg.topic(), msg.partition(), msg.offset())
                    continue

                # Run non-blocking scoring coroutine
                loop.run_until_complete(self._process_with_retries(tx, raw_val, msg.topic(), msg.partition(), msg.offset()))

        except KeyboardInterrupt:
            logger.info("[KafkaWorker] Interrupted by user.")
        except Exception as e:
            logger.critical(f"[KafkaWorker] Fatal loop exception: {e}")
        finally:
            logger.info("[KafkaWorker] Closing Kafka consumer...")
            try:
                consumer.close()
            except Exception:
                pass

    def stop(self):
        self.running = False


# Standalone runner entrypoint (`python -m services.kafka_consumer_service`)
if __name__ == "__main__":
    logger.info("Starting standalone VaultMind Kafka Consumer Worker Service...")
    worker = KafkaConsumerWorker()
    worker.start()
