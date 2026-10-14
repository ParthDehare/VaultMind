import sqlite3
import pandas as pd

conn = sqlite3.connect('vaultmind_ledger.db')
tables = pd.read_sql_query("SELECT name FROM sqlite_master WHERE type='table';", conn)
print("Tables:", tables['name'].tolist())

for table in tables['name']:
    print(f"\n--- {table} ---")
    df = pd.read_sql_query(f"SELECT * FROM {table} LIMIT 5", conn)
    print(df)
