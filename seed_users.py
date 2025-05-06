# seed_users.py
import mysql.connector
import bcrypt
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database credentials
db_host = os.getenv("DB_HOST", "localhost")
db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_name = os.getenv("DB_NAME")

# User data
users = [
    {"email": "admin@example.com", "password": "AdminPass123", "role": "admin"},
    {"email": "seller@example.com", "password": "SellerPass123", "role": "seller"},
    {"email": "buyer@example.com", "password": "BuyerPass123", "role": "buyer"},
]

conn = None
cursor = None

try:
    # Establish database connection
    print(f"Attempting to connect to database '{db_name}' at {db_host}...")
    conn = mysql.connector.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        database=db_name
    )
    cursor = conn.cursor()
    print("Database connection established successfully.")

    buyer_id = None

    for user_data in users:
        email = user_data["email"]
        password = user_data["password"].encode('utf-8') # Encode password for bcrypt
        role = user_data["role"]

        # Hash the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password, salt)

        # Insert user into User table (ignore if email exists)
        insert_user_query = """
        INSERT IGNORE INTO User (email, password_hash, role)
        VALUES (%s, %s, %s)
        """
        try:
            cursor.execute(insert_user_query, (email, hashed_password.decode('utf-8'), role))
            if cursor.rowcount > 0:
                print(f"User '{email}' created successfully.")
                # If it's the buyer and was newly inserted, get their ID
                if role == 'buyer':
                    buyer_id = cursor.lastrowid
                    print(f"Retrieved new buyer ID: {buyer_id}")
            else:
                print(f"User '{email}' already exists.")
                # If buyer already exists, find their ID
                if role == 'buyer' and buyer_id is None: # Only query if ID not already set from insertion
                    find_buyer_query = "SELECT id FROM User WHERE email = %s"
                    cursor.execute(find_buyer_query, (email,))
                    result = cursor.fetchone()
                    if result:
                        buyer_id = result[0]
                        print(f"Found existing buyer ID: {buyer_id}")
                    else:
                         print(f"Could not find existing buyer ID for {email}, wallet cannot be created.")


        except mysql.connector.Error as err:
            print(f"Error inserting user {email}: {err}")
            conn.rollback() # Rollback on error for this user

    # Insert wallet for the buyer if ID was found/created
    if buyer_id:
        insert_wallet_query = """
        INSERT IGNORE INTO Wallet (user_id, balance_cents)
        VALUES (%s, %s)
        """
        initial_balance = 100000
        try:
            cursor.execute(insert_wallet_query, (buyer_id, initial_balance))
            if cursor.rowcount > 0:
                print(f"Wallet created for buyer ID {buyer_id} with balance {initial_balance}.")
            else:
                print(f"Wallet for buyer ID {buyer_id} already exists.")
        except mysql.connector.Error as err:
            print(f"Error inserting wallet for buyer ID {buyer_id}: {err}")
            conn.rollback() # Rollback wallet insertion on error

    # Commit the changes
    conn.commit()
    print("Database changes committed.")

except mysql.connector.Error as err:
    print(f"Database connection error: {err}")
    if conn and conn.is_connected():
        conn.rollback() # Rollback if any error occurred before commit

finally:
    # Close the cursor and connection
    if cursor:
        cursor.close()
        print("Database cursor closed.")
    if conn and conn.is_connected():
        conn.close()
        print("Database connection closed.")