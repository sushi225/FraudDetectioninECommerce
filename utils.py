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
    """Logs an activity to the activity_log table."""
    if not conn:
        print("Error: Database connection is not available for logging.")
        return

    cursor = None
    try:
        cursor = conn.cursor()
        query = """
        INSERT INTO activity_log (user_id, action, timestamp, details)
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
    """Checks if a user is currently blacklisted by checking the User.status field."""
    if not conn or user_id is None:
        print("Error: Database connection or user_id is not available for blacklist check.")
        # Default to True (blacklisted) for safety if we can't verify status.
        # Consider if this default is appropriate for all call sites or if errors should propagate.
        return True

    cursor = None
    try:
        cursor = conn.cursor(dictionary=True) # Use dictionary cursor to access by column name
        query = "SELECT `status` FROM `User` WHERE `id` = %s"
        cursor.execute(query, (user_id,))
        user_record = cursor.fetchone()

        if user_record:
            return user_record['status'] == 'blacklisted'
        else:
            # User not found, this is an issue. For safety, treat as blacklisted.
            print(f"Warning: User ID {user_id} not found during blacklist check.")
            return True
    except mysql.connector.Error as err:
        print(f"Error checking user status for blacklist: {err}")
        # On database error, assume blacklisted for safety.
        return True
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
def get_detected_anomalies(conn, limit=100):
    """
    Fetches anomaly logs from the detected_anomalies table, including the associated user's email.

    Args:
        conn: An active database connection object.
        limit (int, optional): The maximum number of log entries to fetch. Defaults to 100.

    Returns:
        list: A list of dictionaries, where each dictionary represents an anomaly log.
              Returns an empty list if no logs are found or an error occurs.
    """
    if not conn:
        print("Error: Database connection is not available for fetching detected anomalies.")
        return []

    cursor = None
    try:
        # Ensure limit is an integer
        try:
            limit = int(limit)
            if limit <= 0: # Corrected line
                limit = 100 # Default to 100 if invalid limit is provided
        except ValueError:
            print(f"Warning: Invalid limit value provided. Defaulting to 100.")
            limit = 100

        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT
            da.anomaly_id,
            da.user_id,
            u.email AS user_email,
            da.user_type,
            da.anomaly_type,
            da.detection_timestamp,
            da.details
        FROM detected_anomalies da
        LEFT JOIN User u ON da.user_id = u.id
        ORDER BY da.detection_timestamp DESC
        LIMIT %s;
        """
        cursor.execute(query, (limit,))
        anomalies = cursor.fetchall()
        return anomalies
    except mysql.connector.Error as err:
        print(f"Error fetching detected anomalies: {err}")
        return []
    finally:
        if cursor:
            cursor.close()