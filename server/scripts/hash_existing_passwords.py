import os
import sys
from dotenv import load_dotenv
from supabase import create_client, Client
import bcrypt

# Load environment variables from the server directory
server_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(server_dir, ".env"))

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("Error: Missing SUPABASE_URL or SUPABASE_KEY in environment.")
    sys.exit(1)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
# Removed passlib context

def main():
    print("Fetching existing users from Supabase 'bank_employees' table...")
    try:
        response = supabase.table("bank_employees").select("*").execute()
        users = response.data
    except Exception as e:
        print(f"Failed to fetch users: {e}")
        return

    if not users:
        print("No users found.")
        return

    updated_count = 0
    for user in users:
        emp_id = user.get("emp_id")
        password = user.get("password")

        if not password:
            continue

        # Check if already a bcrypt hash (usually starts with $2b$, $2a$, or $2y$)
        if password.startswith("$2b$") or password.startswith("$2a$") or password.startswith("$2y$"):
            print(f"Skipping {emp_id} - already hashed.")
            continue

        print(f"Hashing password for {emp_id}...")
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update the database
        try:
            update_response = supabase.table("bank_employees").update({"password": hashed_pw}).eq("emp_id", emp_id).execute()
            if update_response.data:
                print(f"Successfully updated {emp_id}.")
                updated_count += 1
            else:
                print(f"Failed to update {emp_id}.")
        except Exception as e:
            print(f"Error updating {emp_id}: {e}")

    print(f"Done. Updated {updated_count} passwords.")

if __name__ == "__main__":
    main()
