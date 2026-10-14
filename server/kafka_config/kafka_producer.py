# vaultmind_producer.py
import time
import json
from pathlib import Path
import pandas as pd
from kafka import KafkaProducer

import uuid

# Initialize Kafka Producer
# Make sure to run: pip install kafka-python pandas
import os
producer = None
for attempt in range(5):
    try:
        producer = KafkaProducer(
            bootstrap_servers=[os.environ.get('KAFKA_BROKER', 'localhost:9092')],
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            api_version=(2, 5, 0),
            retries=5
        )
        print("[OK] Kafka Producer Connected Successfully!")
        break
    except Exception as e:
        print(f"[ERROR] Kafka Connection Failed (Attempt {attempt + 1}/5): {e}")
        time.sleep(2)

if not producer:
    print("[WARNING] Could not connect to Kafka. Producer running in dummy mode.")

TOPIC_NAME = "live-transactions"
BASE_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = str(BASE_DIR / "data" / "Testing_data" / "live_demo_stream.csv")


def stream_data():
    print(f"[INFO] Starting Live Stream from {CSV_FILE} to Kafka Topic: {TOPIC_NAME}...")
    try:
        # Load the mock dataset
        df = pd.read_csv(CSV_FILE)
        
        while True:
            for index, row in df.iterrows():
                transaction = row.to_dict()
                
                # Regenerate transaction ID for infinite looping
                transaction['transaction_id'] = str(uuid.uuid4())
                
                # Send to Kafka
                if producer:
                    producer.send(TOPIC_NAME, transaction)
                print(f"[STREAM] Sent Tx: {transaction.get('transaction_id', 'UNKNOWN')} | Acc: {transaction.get('source_account', 'N/A')}")
                
                # Simulate real-time delay (1.5 seconds per transaction)
                time.sleep(1.5)
            
    except FileNotFoundError:
        print(f"[ERROR] Could not find {CSV_FILE}. Please make sure the dataset exists.")
    except KeyboardInterrupt:
        print("\n[STOP] Streaming Stopped by User.")
    finally:
        producer.close()

if __name__ == "__main__":
    stream_data()