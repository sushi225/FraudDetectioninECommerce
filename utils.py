import mysql.connector
import datetime
import os
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env file

def get_db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            autocommit=True
        )
        return conn
    except mysql.connector.Error as err:
        print(f"Error connecting to database: {err}")
        return None

def log_activity(conn, user_id, action, details="", commit_now=True):
    """Logs an activity to the LoggingActivity table."""
    if not conn:
        print("Error: Database connection is not available for logging.")
        return

    cursor = None
    try:
        cursor = conn.cursor()
        query = """
        INSERT INTO LoggingActivity (user_id, action, timestamp, details)
        VALUES (%s, %s, %s, %s)
        """
        timestamp = datetime.datetime.now()
        cursor.execute(query, (user_id, action, timestamp, details))
        if commit_now:
            conn.commit()
    except mysql.connector.Error as err:
        print(f"Error logging activity: {err}")
        # Optionally rollback if needed, though commit might fail anyway
        # conn.rollback()
    finally:
        if cursor:
            cursor.close()

def check_blacklist(conn, user_id):
    """Checks if a user is currently blacklisted."""
    if not conn or user_id is None:
        print("Error: Database connection or user_id is not available for blacklist check.")
        return False # Assume not blacklisted if we can't check

    cursor = None
    try:
        cursor = conn.cursor()
        query = """
        SELECT 1 FROM Blacklist
        WHERE user_id = %s
        AND (blocked_until IS NULL OR blocked_until > %s)
        LIMIT 1
        """
        now = datetime.datetime.now()
        cursor.execute(query, (user_id, now))
        result = cursor.fetchone()
        return result is not None # True if a record is found
    except mysql.connector.Error as err:
        print(f"Error checking blacklist: {err}")
        return False # Assume not blacklisted on error
    finally:
        if cursor:
            cursor.close()
def get_all_reviews(conn):
    """Fetches all reviews with product name and buyer email."""
    if not conn:
        print("Error: Database connection is not available for fetching all reviews.")
        return []
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT
            r.id,
            p.name AS product_name,
            u.email AS buyer_email,
            r.rating,
            r.text,
            r.created_at AS review_date
        FROM Review r
        JOIN Product p ON r.product_id = p.id
        JOIN User u ON r.buyer_id = u.id
        ORDER BY review_date DESC;
        """
        cursor.execute(query)
        reviews = cursor.fetchall()
        return reviews
    except mysql.connector.Error as err:
        print(f"Error fetching all reviews: {err}")
        return []
    finally:
        if cursor:
            cursor.close()
def get_all_customer_tickets(conn):
    """Fetches all customer support tickets with buyer email."""
    if not conn:
        print("Error: Database connection is not available for fetching all customer tickets.")
        return []
    cursor = None
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT
            cs.id,
            u.email AS buyer_email,
            cs.issue_type AS subject,
            cs.description,
            cs.status,
            cs.created_at,
            cs.order_id
        FROM CustomerSupport cs
        JOIN User u ON cs.buyer_id = u.id
        ORDER BY cs.created_at DESC;
        """
        cursor.execute(query)
        tickets = cursor.fetchall()
        return tickets
    except mysql.connector.Error as err:
        print(f"Error fetching all customer tickets: {err}")
        return []
    finally:
        if cursor:
            cursor.close()