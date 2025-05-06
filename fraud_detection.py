import mysql.connector
import datetime
from datetime import timedelta
from utils import log_activity, get_db_connection # Assuming get_db_connection might be needed if not passed

def log_anomaly(conn, event_type, reference_id, rule_triggered, score=None):
    """Logs a detected anomaly to the AnomalyDetectionLog table."""
    if not conn:
        print("Error: Database connection is not available for anomaly logging.")
        return

    cursor = None
    try:
        cursor = conn.cursor()
        query = """
        INSERT INTO AnomalyDetectionLog (event_type, reference_id, rule_triggered, score, timestamp)
        VALUES (%s, %s, %s, %s, %s)
        """
        timestamp = datetime.datetime.now()
        cursor.execute(query, (event_type, reference_id, rule_triggered, score, timestamp))
        # conn.commit() # Removed commit: This should be part of the calling transaction
        # Also log this detection event itself using log_activity, without committing here
        log_activity(conn, None, 'anomaly_detected', f"Rule: {rule_triggered}, Event: {event_type}, Ref: {reference_id}", commit_now=False)
    except mysql.connector.Error as err:
        print(f"Error logging anomaly: {err}")
        # conn.rollback() # Consider rollback if the transaction needs atomicity
    finally:
        if cursor:
            cursor.close()

# --- Individual Fraud Rule Check Functions ---

def check_multiple_low_ratings(conn, product_id):
    """Checks for >= 3 reviews with rating <= 2 for the same product within 24 hours."""
    if not conn or product_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(hours=24)
        query = """
        SELECT COUNT(*) FROM Review -- Corrected table name
        WHERE product_id = %s
        AND rating <= 2
        AND created_at >= %s -- Corrected column name
        """
        cursor.execute(query, (product_id, time_threshold))
        count = cursor.fetchone()[0]
        return count >= 3
    except mysql.connector.Error as err:
        print(f"Error checking multiple low ratings: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_repeat_reviews(conn, buyer_id, product_id):
    """Checks if the same buyer has reviewed the same product more than once (across different orders)."""
    # This rule might need refinement. Does it mean *any* two reviews ever? Or within a timeframe?
    # Assuming it means more than one review exists *ever* for the buyer/product combo.
    if not conn or buyer_id is None or product_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        query = """
        SELECT COUNT(*) FROM Review -- Corrected table name
        WHERE buyer_id = %s
        AND product_id = %s
        """
        cursor.execute(query, (buyer_id, product_id))
        count = cursor.fetchone()[0]
        return count > 1
    except mysql.connector.Error as err:
        print(f"Error checking repeat reviews: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_rapid_orders(conn, buyer_id, seller_id):
    """Checks for >= 5 orders from the same buyer to the same seller within 1 hour."""
    if not conn or buyer_id is None or seller_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(hours=1)
        # Need to join Orders with Products to get seller_id
        query = """
        SELECT COUNT(o.id) -- Assuming o.id is the primary key for Order
        FROM `Order` o -- Corrected table name
        JOIN Product p ON o.product_id = p.id -- Assuming p.id is the primary key for Product
        WHERE o.user_id = %s -- Assuming o.user_id is the buyer
        AND p.seller_id = %s
        AND o.created_at >= %s -- Corrected column name
        """
        cursor.execute(query, (buyer_id, seller_id, time_threshold))
        count = cursor.fetchone()[0]
        return count >= 5
    except mysql.connector.Error as err:
        print(f"Error checking rapid orders: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_rapid_transactions(conn, buyer_id, product_id, amount_cents):
    """Checks for >= 2 transactions for the same product and amount within 10 minutes."""
    if not conn or buyer_id is None or product_id is None or amount_cents is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(minutes=10)
        # Assuming Transactions table has buyer_id, product_id, amount_cents, and timestamp
        query = """
        SELECT COUNT(*) FROM Transaction -- Corrected table name
        WHERE buyer_id = %s
        AND product_id = %s
        AND amount_cents = %s
        AND timestamp >= %s -- Corrected column name
        """
        cursor.execute(query, (buyer_id, product_id, amount_cents, time_threshold))
        count = cursor.fetchone()[0]
        return count >= 2
    except mysql.connector.Error as err:
        print(f"Error checking rapid transactions: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_multiple_not_delivered(conn, buyer_id):
    """Checks for >= 3 'not delivered' support tickets from the same buyer within 24 hours."""
    if not conn or buyer_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(hours=24)
        # Assuming SupportTickets table has buyer_id, issue_type, and created_at timestamp
        query = """
        SELECT COUNT(*) FROM CustomerSupport -- Corrected table name
        WHERE buyer_id = %s
        AND status = 'open' -- Corrected status value
        AND description LIKE '%not delivered%' -- Assuming 'description' field for issue text
        AND created_at >= %s
        """
        cursor.execute(query, (buyer_id, time_threshold))
        count = cursor.fetchone()[0]
        return count >= 3
    except mysql.connector.Error as err:
        print(f"Error checking multiple not delivered tickets: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_self_purchase(conn, buyer_id, product_id):
    """Checks if the buyer is purchasing a product listed by their own seller account."""
    if not conn or buyer_id is None or product_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        # Get the seller_id for the product
        query = "SELECT seller_id FROM Product WHERE id = %s" # Corrected table and column name
        cursor.execute(query, (product_id,))
        result = cursor.fetchone()
        if result:
            seller_id = result[0]
            # Check if buyer_id matches seller_id (assuming buyer_id and seller_id reference the same Users table)
            return buyer_id == seller_id
        return False # Product not found
    except mysql.connector.Error as err:
        print(f"Error checking self purchase: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_rapid_logins(conn, user_id):
    """Checks for another successful login for the same user within the last hour."""
    if not conn or user_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(hours=1)
        # Check LoggingActivity for recent 'login' actions by the same user
        query = """
        SELECT COUNT(*) FROM LoggingActivity
        WHERE user_id = %s
        AND action = 'login'
        AND timestamp >= %s
        """
        # We might need to exclude the *current* login event if it's logged before this check runs.
        # This simplified version counts *any* login in the window.
        cursor.execute(query, (user_id, time_threshold))
        # If count > 1, it means there was at least one other login recently.
        # If the current login is logged *before* this check, we look for count > 1.
        # If the current login is logged *after* this check, we look for count >= 1.
        # Assuming login is logged *before* check:
        count = cursor.fetchone()[0]
        return count > 1 # More than the current login event
    except mysql.connector.Error as err:
        print(f"Error checking rapid logins: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_cart_flapping(conn, user_id):
    """Checks for > 5 cart add/remove actions by the same user within 5 minutes."""
    if not conn or user_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(minutes=5)
        # Check LoggingActivity for recent 'cart_add'/'cart_remove' actions
        query = """
        SELECT COUNT(*) FROM LoggingActivity
        WHERE user_id = %s
        AND action IN ('cart_add', 'cart_remove') -- Assuming these action names
        AND timestamp >= %s
        """
        cursor.execute(query, (user_id, time_threshold))
        count = cursor.fetchone()[0]
        return count > 5
    except mysql.connector.Error as err:
        print(f"Error checking cart flapping: {err}")
        return False
    finally:
        if cursor:
            cursor.close()


# --- Central Fraud Check Runner ---

def run_fraud_checks(conn, event_type, data):
    """Runs relevant fraud checks based on the event type and logs anomalies."""
    if not conn:
        print("Error: Database connection not available for fraud checks.")
        return

    triggered_rules = []

    # --- Review Event ---
    if event_type == 'new_review':
        product_id = data.get('product_id')
        buyer_id = data.get('buyer_id')
        review_id = data.get('review_id') # Reference ID for anomaly

        if product_id and check_multiple_low_ratings(conn, product_id):
            triggered_rules.append(('check_multiple_low_ratings', review_id))

        if buyer_id and product_id and check_repeat_reviews(conn, buyer_id, product_id):
            triggered_rules.append(('check_repeat_reviews', review_id))

    # --- Order/Transaction Event ---
    elif event_type == 'new_order' or event_type == 'new_transaction':
        buyer_id = data.get('buyer_id')
        seller_id = data.get('seller_id') # May need to fetch based on product_id
        product_id = data.get('product_id')
        amount_cents = data.get('amount_cents')
        order_id = data.get('order_id') # Reference ID
        transaction_id = data.get('transaction_id') # Reference ID

        ref_id = order_id if event_type == 'new_order' else transaction_id

        # Fetch seller_id if not provided directly
        if not seller_id and product_id:
             cursor = conn.cursor()
             try:
                 cursor.execute("SELECT seller_id FROM Product WHERE id = %s", (product_id,)) # Corrected table and column name
                 result = cursor.fetchone()
                 if result: seller_id = result[0]
             except mysql.connector.Error as err:
                 print(f"Error fetching seller_id for fraud check: {err}")
             finally:
                 if cursor: cursor.close()


        if buyer_id and seller_id and check_rapid_orders(conn, buyer_id, seller_id):
             triggered_rules.append(('check_rapid_orders', ref_id))

        if buyer_id and product_id and amount_cents and check_rapid_transactions(conn, buyer_id, product_id, amount_cents):
             triggered_rules.append(('check_rapid_transactions', ref_id))

        if buyer_id and product_id and check_self_purchase(conn, buyer_id, product_id):
             triggered_rules.append(('check_self_purchase', ref_id))

    # --- Support Ticket Event ---
    elif event_type == 'new_support_ticket':
        buyer_id = data.get('buyer_id')
        ticket_id = data.get('ticket_id') # Reference ID
        issue = data.get('issue', '').lower()

        # Check only if the ticket seems related to non-delivery
        if buyer_id and 'not delivered' in issue and check_multiple_not_delivered(conn, buyer_id):
            triggered_rules.append(('check_multiple_not_delivered', ticket_id))

    # --- Login Event ---
    elif event_type == 'login':
        user_id = data.get('user_id')
        # Assuming login activity is logged *before* this check runs
        if user_id and check_rapid_logins(conn, user_id):
             # Reference ID might be the user_id or a specific session/log ID if available
             triggered_rules.append(('check_rapid_logins', user_id))

    # --- Cart Action Event ---
    elif event_type == 'cart_action': # Assuming 'cart_add' or 'cart_remove' triggers this
        user_id = data.get('user_id')
        # Reference ID could be user_id or a specific cart action log ID
        if user_id and check_cart_flapping(conn, user_id):
            triggered_rules.append(('check_cart_flapping', user_id))

    # --- Log any triggered anomalies ---
    for rule_name, ref_id in triggered_rules:
        log_anomaly(conn, event_type, ref_id, rule_name)

# Example Usage (Illustrative - would be called from app.py or other event handlers)
# if __name__ == '__main__':
#     db_conn = get_db_connection()
#     if db_conn:
#         # Simulate a new review event
#         review_data = {'product_id': 1, 'buyer_id': 2, 'review_id': 101, 'rating': 1}
#         run_fraud_checks(db_conn, 'new_review', review_data)
#
#         # Simulate a login event
#         login_data = {'user_id': 3}
#         # Assume log_activity(db_conn, 3, 'login') was called just before this
#         run_fraud_checks(db_conn, 'login', login_data)
#
#         db_conn.close()