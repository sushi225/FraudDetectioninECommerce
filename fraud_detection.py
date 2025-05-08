print("[MEGA_DEBUG_V1] fraud_detection.py module is being loaded NOW!") # New global print

import mysql.connector
import datetime
from datetime import timedelta
import json # Added for serializing details
from utils import log_activity, get_db_connection # Assuming get_db_connection might be needed if not passed

def log_anomaly_to_detected_anomalies(db_connection, cursor, user_id_val, adl_event_type, anomaly_type_str, details_dict):
    """
    Logs a specific user anomaly to the detected_anomalies table and system activity.
    Uses the provided cursor and db_connection; does not commit here.
    The detected_anomalies table has: user_id, user_type, anomaly_type, details.
    """
    if not db_connection or not cursor:
        print("Error: DB connection or cursor not available for detailed anomaly logging to detected_anomalies.")
        return

    try:
        # timestamp = datetime.datetime.now() # Not needed for detected_anomalies as it has a default CURRENT_TIMESTAMP
        details_json = json.dumps(details_dict) if details_dict is not None else None

        # Log to detected_anomalies table
        da_query = """
        INSERT INTO detected_anomalies (user_id, user_type, anomaly_type, details)
        VALUES (%s, %s, %s, %s)
        """
        # Parameters: user_id_val, adl_event_type (maps to user_type), anomaly_type_str, details_json
        cursor.execute(da_query, (user_id_val, adl_event_type, anomaly_type_str, details_json))

        # Log this detection event itself using log_activity
        log_activity_message = f"UserRoleContext: {adl_event_type}, Rule: {anomaly_type_str}, UserID: {user_id_val}, Details: {details_json} logged to detected_anomalies."
        # Using user_id_val as the reference_id for log_activity as it's user-centric
        log_activity(db_connection, user_id_val, 'user_anomaly_logged_to_da', log_activity_message, commit_now=False)

    except mysql.connector.Error as err:
        print(f"Error in log_anomaly_to_detected_anomalies for user {user_id_val}, rule {anomaly_type_str}: {err}")
        # Rollback should be handled by the main orchestrator if this fails.
        # Re-raise to ensure the orchestrator's error handling is triggered.
        raise
    except Exception as e:
        print(f"Unexpected error in log_anomaly_to_detected_anomalies for user {user_id_val}, rule {anomaly_type_str}: {e}")
        raise


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
    # This is an older version of check_rapid_transactions. The newer one below is used by the orchestrator.
    # This one takes `conn` and creates its own cursor.
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
        print(f"Error checking rapid transactions (old version): {err}")
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
            seller_id_of_product = result[0]
            # Check if buyer_id matches seller_id (assuming buyer_id and seller_id reference the same Users table)
            return buyer_id == seller_id_of_product
        return False # Product not found
    except mysql.connector.Error as err:
        print(f"Error checking self purchase: {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_rapid_logins(conn, user_id):
    """Checks for another successful login for the same user within the last hour."""
    # This is an older version. The newer one `check_multiple_logins` is used by the orchestrator.
    if not conn or user_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(hours=1)
        # Check activity_log for recent 'login' actions by the same user
        query = """
        SELECT COUNT(*) FROM activity_log
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
        print(f"Error checking rapid logins (old version): {err}")
        return False
    finally:
        if cursor:
            cursor.close()

def check_cart_flapping(conn, user_id):
    """Checks for > 5 cart add/remove actions by the same user within 5 minutes."""
    # This is an older version. The newer one `check_cart_flipping` is used by the orchestrator.
    if not conn or user_id is None:
        return False
    cursor = None
    try:
        cursor = conn.cursor()
        time_threshold = datetime.datetime.now() - timedelta(minutes=5)
        # Check activity_log for recent 'cart_add'/'cart_remove' actions
        query = """
        SELECT COUNT(*) FROM activity_log
        WHERE user_id = %s
        AND action IN ('cart_add', 'cart_remove') -- Assuming these action names
        AND timestamp >= %s
        """
        cursor.execute(query, (user_id, time_threshold))
        count = cursor.fetchone()[0]
        return count > 5
    except mysql.connector.Error as err:
        print(f"Error checking cart flapping (old version): {err}")
        return False
    finally:
        if cursor:
            cursor.close()


# --- New User Anomaly Detection Functions (used by orchestrator) ---

def check_multiple_logins(db_cursor, user_id_param): # Renamed buyer_id to user_id_param for clarity
    """
    Checks if a user logs in more than 3 times successfully within a 2-minute window.
    Queries: login_attempts (user_id, login_timestamp, success)
    Uses the passed db_cursor.
    """
    anomaly_type_val = "multiple_logins"
    time_window_minutes = 2
    login_threshold = 3
    
    try:
        time_ago = datetime.datetime.now() - timedelta(minutes=time_window_minutes)
        
        query = """
        SELECT COUNT(*) 
        FROM login_attempts
        WHERE user_id = %s 
          AND success = TRUE 
          AND login_timestamp >= %s
        """
        db_cursor.execute(query, (user_id_param, time_ago))
        login_count_tuple = db_cursor.fetchone()
        login_count = login_count_tuple[0] if login_count_tuple else 0
        
        if login_count > login_threshold:
            return {
                'is_anomaly': True,
                'anomaly_type': anomaly_type_val,
                'details': {
                    'login_count': login_count,
                    'time_window_minutes': time_window_minutes,
                    'user_id': user_id_param
                }
            }
        else:
            return {
                'is_anomaly': False,
                'anomaly_type': None, # anomaly_type_val can be returned for context if needed
                'details': None
            }
    except mysql.connector.Error as e:
        print(f"Error in {anomaly_type_val} check for user_id {user_id_param}: {e}")
        return {
            'is_anomaly': False,
            'anomaly_type': None,
            'details': {'error': str(e)}
        }

def check_rapid_transactions(db_cursor, user_id_param): # Renamed buyer_id to user_id_param
    """
    Checks if a buyer completes more than 3 transactions (checkouts) within a 1-minute window.
    Queries: Order (user_id, created_at) - Assuming 'Order' table represents checkouts.
    Uses the passed db_cursor.
    """
    anomaly_type_val = "rapid_transactions_buyer" # Made more specific
    time_window_minutes = 1
    transaction_threshold = 3
    
    try:
        time_ago = datetime.datetime.now() - timedelta(minutes=time_window_minutes)
        
        query = """
        SELECT COUNT(*) 
        FROM `Order` 
        WHERE user_id = %s 
          AND created_at >= %s
        """
        db_cursor.execute(query, (user_id_param, time_ago))
        transaction_count_tuple = db_cursor.fetchone()
        transaction_count = transaction_count_tuple[0] if transaction_count_tuple else 0
        
        if transaction_count > transaction_threshold:
            return {
                'is_anomaly': True,
                'anomaly_type': anomaly_type_val,
                'details': {
                    'transaction_count': transaction_count,
                    'time_window_minutes': time_window_minutes,
                    'user_id': user_id_param
                }
            }
        else:
            return {
                'is_anomaly': False,
                'anomaly_type': None,
                'details': None
            }
    except mysql.connector.Error as e:
        print(f"Error in {anomaly_type_val} check for user_id {user_id_param}: {e}")
        return {
            'is_anomaly': False,
            'anomaly_type': None,
            'details': {'error': str(e)}
        }

def check_cart_flipping(db_cursor, user_id_param): # Renamed buyer_id to user_id_param
    """
    Checks if a buyer rapidly adds more than 6 items to the cart (distinct 'add' events)
    within a 1-minute window.
    Queries: cart_events (buyer_id, event_type='add', event_timestamp)
    Uses the passed db_cursor.
    """
    anomaly_type_val = "cart_flipping_buyer" # Made more specific
    time_window_minutes = 1
    items_added_threshold = 6
    
    try:
        time_ago = datetime.datetime.now() - timedelta(minutes=time_window_minutes)
        
        # cart_events table uses buyer_id
        query = """
        SELECT COUNT(*)
        FROM cart_events
        WHERE buyer_id = %s  -- Corrected to buyer_id as per cart_events schema
          AND event_type = 'add'
          AND event_timestamp >= %s
        """
        db_cursor.execute(query, (user_id_param, time_ago))
        items_added_count_tuple = db_cursor.fetchone()
        items_added_count = items_added_count_tuple[0] if items_added_count_tuple else 0
        
        if items_added_count > items_added_threshold:
            return {
                'is_anomaly': True,
                'anomaly_type': anomaly_type_val,
                'details': {
                    'items_added_count': items_added_count,
                    'time_window_minutes': time_window_minutes,
                    'user_id': user_id_param
                }
            }
        else:
            return {
                'is_anomaly': False,
                'anomaly_type': None,
                'details': None
            }
    except mysql.connector.Error as e:
        print(f"Error in {anomaly_type_val} check for user_id {user_id_param}: {e}")
        return {
            'is_anomaly': False,
            'anomaly_type': None,
            'details': {'error': str(e)}
        }

def check_multiple_poor_reviews(db_cursor, seller_user_id): # Renamed seller_id to seller_user_id
    """
    Checks if a seller receives more than 2 bad reviews (rating <= 2) 
    across 3 or more different products.
    Queries: Review (seller_id, product_id, rating)
    Uses the passed db_cursor.
    """
    anomaly_type_val = "multiple_poor_reviews_seller"
    bad_review_threshold = 2 # More than 2 means >= 3
    distinct_product_threshold = 3
    
    try:
        # 1. Count total bad reviews for the seller
        query_total_bad_reviews = """
        SELECT COUNT(*) 
        FROM Review
        WHERE seller_id = %s 
          AND rating <= 2
        """
        db_cursor.execute(query_total_bad_reviews, (seller_user_id,))
        total_bad_review_count_tuple = db_cursor.fetchone()
        total_bad_review_count = total_bad_review_count_tuple[0] if total_bad_review_count_tuple else 0
        
        # 2. Count distinct products with bad reviews for the seller
        query_distinct_products_with_bad_reviews = """
        SELECT COUNT(DISTINCT product_id) 
        FROM Review
        WHERE seller_id = %s 
          AND rating <= 2
        """
        db_cursor.execute(query_distinct_products_with_bad_reviews, (seller_user_id,))
        distinct_product_count_tuple = db_cursor.fetchone()
        distinct_product_count = distinct_product_count_tuple[0] if distinct_product_count_tuple else 0
        
        if total_bad_review_count > bad_review_threshold and \
           distinct_product_count >= distinct_product_threshold:
            return {
                'is_anomaly': True,
                'anomaly_type': anomaly_type_val,
                'details': {
                    'bad_review_count': total_bad_review_count,
                    'distinct_product_count_with_bad_reviews': distinct_product_count,
                    'seller_user_id': seller_user_id
                }
            }
        else:
            return {
                'is_anomaly': False,
                'anomaly_type': None,
                'details': None
            }
    except mysql.connector.Error as e:
        print(f"Error in {anomaly_type_val} check for seller_user_id {seller_user_id}: {e}")
        return {
            'is_anomaly': False,
            'anomaly_type': None,
            'details': {'error': str(e)}
        }

def check_multiple_item_not_received_tickets(db_cursor, user_id_param): # Renamed buyer_id to user_id_param
    """
    Checks if a buyer submits more than 3 customer support tickets 
    with issue_type "Item not Received".
    Queries: CustomerSupport (buyer_id, issue_type) - Assuming buyer_id is user_id
    Uses the passed db_cursor.
    """
    anomaly_type_val = "item_not_received_tickets_buyer"
    ticket_threshold = 3 # More than 3 means >= 4
    
    try:
        time_ago = datetime.datetime.now() - timedelta(minutes=10) # Example: within last 10 mins, adjust as needed
                                                                # The problem description for this rule did not specify a time window.
                                                                # Let's assume it's "ever" or a very large window if not specified.
                                                                # For now, let's count all such tickets.
        
        query = """
        SELECT COUNT(*) 
        FROM CustomerSupport
        WHERE buyer_id = %s 
          AND issue_type = 'Item not Received' 
        """ # Removed time_ago for now, assuming all tickets count
        db_cursor.execute(query, (user_id_param,))
        ticket_count_tuple = db_cursor.fetchone()
        ticket_count = ticket_count_tuple[0] if ticket_count_tuple else 0
        
        if ticket_count > ticket_threshold:
            return {
                'is_anomaly': True,
                'anomaly_type': anomaly_type_val,
                'details': {
                    'ticket_count': ticket_count,
                    'issue_type': "Item not Received",
                    'user_id': user_id_param
                }
            }
        else:
            return {
                'is_anomaly': False,
                'anomaly_type': None,
                'details': None
            }
    except mysql.connector.Error as e:
        print(f"Error in {anomaly_type_val} check for user_id {user_id_param}: {e}")
        return {
            'is_anomaly': False,
            'anomaly_type': None,
            'details': {'error': str(e)}
        }


# --- Orchestrator for User Anomaly Detection ---
# This orchestrator is called when a user context is available (e.g., after login, during checkout)

# Mapping user roles to relevant check functions
# This defines which checks apply to which user roles during general activity.
USER_ROLE_TO_ANOMALY_CHECKS = {
    'buyer': [
        check_multiple_logins,
        check_rapid_transactions, # Buyer-specific context
        check_cart_flipping,      # Buyer-specific context
        check_multiple_item_not_received_tickets # Buyer-specific context
    ],
    'seller': [
        check_multiple_logins,
        check_multiple_poor_reviews # Seller-specific context
    ],
    'user': [ # Generic user, might be less specific or a fallback
        check_multiple_logins
    ]
    # Admin users are typically not subject to these automated checks.
}


def run_fraud_checks(conn, event_type, data):
    """
    Main function to run fraud checks based on event type.
    This is a placeholder and needs to be expanded based on specific events.
    It now calls the new orchestrator if user context is available.
    """
    if not conn:
        print("Error: Database connection not provided to run_fraud_checks.")
        return

    user_id = data.get('user_id')
    user_role = data.get('user_role') # e.g., 'buyer', 'seller'

    # If user context is available, run user-specific anomaly checks
    if user_id is not None and user_role is not None:
        print(f"Running user anomaly checks for user_id: {user_id}, role: {user_role} due to event: {event_type}")
        run_all_user_anomaly_checks_and_log(conn, user_id, user_role)
    else:
        print(f"No specific user context (user_id/role) for event {event_type}, skipping user anomaly checks via orchestrator.")


    # Example: Placeholder for other event-specific checks (non-user-centric)
    if event_type == 'new_review':
        product_id = data.get('product_id')
        buyer_id = data.get('buyer_id') # Assuming buyer_id is the user_id who wrote the review
        if check_multiple_low_ratings(conn, product_id):
            # log_anomaly(conn, event_type, product_id, "multiple_low_ratings_on_product") # Call removed
            # Potentially log to detected_anomalies if we can link it to a user (e.g., seller of product)
            pass # Functionality covered by newer checks or needs refactoring for proper context
        if buyer_id and check_repeat_reviews(conn, buyer_id, product_id):
            # log_anomaly(conn, event_type, buyer_id, "repeat_review_by_buyer") # Call removed
            # Log to detected_anomalies for the buyer
            # This requires a cursor from the main transaction, or careful handling.
            # For simplicity, the generic log_anomaly is used here.
            # To use log_anomaly_to_detected_anomalies, this function would need a cursor
            # or the main caller of run_fraud_checks would manage the transaction and cursor.
            pass # Functionality covered by newer checks


    elif event_type == 'new_order':
        buyer_id = data.get('buyer_id')
        seller_id = data.get('seller_id') # This needs to be derived, e.g., from product in order
        product_id = data.get('product_id') # Assuming single product order for self-purchase check

        if buyer_id and seller_id and check_rapid_orders(conn, buyer_id, seller_id):
            # log_anomaly(conn, event_type, buyer_id, "rapid_orders_buyer_to_seller") # Call removed
            pass # Functionality covered by newer checks

        if buyer_id and product_id and check_self_purchase(conn, buyer_id, product_id):
            # log_anomaly(conn, event_type, buyer_id, "self_purchase_attempt") # Call removed
            # Consider logging to detected_anomalies for the buyer_id (who is also the seller)
            pass # Functionality covered by newer checks

    elif event_type == 'new_support_ticket':
        buyer_id = data.get('buyer_id')
        if buyer_id and check_multiple_not_delivered(conn, buyer_id): # This is an older check
            # log_anomaly(conn, event_type, buyer_id, "multiple_not_delivered_tickets_buyer_old_check") # Call removed
            # The new orchestrator handles a similar check: check_multiple_item_not_received_tickets
            pass # Functionality covered by newer checks

    # Note: Some older checks like check_rapid_logins, check_cart_flapping are superseded by
    # the new checks (check_multiple_logins, check_cart_flipping) called by the orchestrator.
    # This run_fraud_checks function acts as a simple dispatcher for now.
    # A more robust system would have clearly defined events and associated checks.

    print(f"Fraud checks for event '{event_type}' completed.")


def run_all_user_anomaly_checks_and_log(db_connection, user_id, user_role):
    """
    Orchestrates running all applicable anomaly checks for a given user and logs findings.
    This function manages its own transaction for logging anomalies if any are found.
    If multiple anomalies are found, they are logged within the same transaction.
    """
    if not db_connection:
        print("Error: DB connection not available for run_all_user_anomaly_checks_and_log.")
        return {'total_anomalies_found': 0, 'anomalies_logged': 0}

    # Determine which set of checks to run based on user_role
    # Fallback to 'user' role checks if specific role has no checks or role is unknown
    check_functions_for_role = USER_ROLE_TO_ANOMALY_CHECKS.get(user_role, USER_ROLE_TO_ANOMALY_CHECKS.get('user', []))

    if not check_functions_for_role:
        print(f"No anomaly checks defined for user_role: {user_role} or default 'user' role.")
        return {'total_anomalies_found': 0, 'anomalies_logged': 0}

    anomalies_found_count = 0
    anomalies_logged_count = 0
    
    # Use a single cursor for all checks within this orchestration if they share a transaction for logging
    # However, each check function currently creates its own cursor or is passed one.
    # The new check functions (check_multiple_logins etc.) are designed to be passed a cursor.
    # This orchestrator will create a cursor to pass to these check functions
    # and manage the transaction for logging anomalies.

    cursor = None
    try:
        cursor = db_connection.cursor() # Standard cursor for checks

        for check_function in check_functions_for_role:
            try:
                # Assuming check_function takes (db_cursor, user_id)
                # Adjust if signature varies (e.g. some might take db_connection instead of cursor, or more params)
                # The new style checks (check_multiple_logins, etc.) take (db_cursor, user_id_param)
                anomaly_result = check_function(cursor, user_id)
                
                if anomaly_result and anomaly_result.get('is_anomaly'):
                    anomalies_found_count += 1
                    anomaly_type = anomaly_result.get('anomaly_type', 'unknown_anomaly')
                    details = anomaly_result.get('details', {})
                    
                    print(f"User Anomaly Detected for user_id {user_id} (Role: {user_role}): {anomaly_type}, Details: {json.dumps(details)}")
                    
                    # Log to detected_anomalies table using the shared cursor
                    # The adl_event_type here can be the user_role or a more specific context if available
                    log_anomaly_to_detected_anomalies(db_connection, cursor, user_id, user_role, anomaly_type, details)
                    anomalies_logged_count += 1
                    
            except Exception as e: # Catch errors from individual check functions
                print(f"Error executing check function {check_function.__name__} for user {user_id}: {e}")
                # Optionally log this error or re-raise if critical
                # For now, continue to other checks

        if anomalies_logged_count > 0:
            # If any anomalies were logged by log_anomaly_to_detected_anomalies, commit them.
            # log_anomaly_to_detected_anomalies itself does not commit.
            try:
                db_connection.commit()
                print(f"Committed {anomalies_logged_count} logged anomalies for user {user_id}.")
            except mysql.connector.Error as commit_err:
                print(f"Error committing logged anomalies for user {user_id}: {commit_err}")
                try:
                    db_connection.rollback() # Rollback if commit failed
                except mysql.connector.Error as rb_err:
                    print(f"Error during rollback after commit failure: {rb_err}")
        else:
            # If no anomalies were logged, but checks ran, no commit/rollback needed for anomaly logging part.
            # Any SELECT queries in checks don't modify data.
            pass
            
    except mysql.connector.Error as db_err:
        print(f"Database error during anomaly check orchestration for user {user_id}: {db_err}")
        if db_connection:
            try:
                db_connection.rollback() # Rollback any potential partial changes if an error occurred mid-process
            except mysql.connector.Error as rb_err:
                print(f"Error during rollback in main orchestrator: {rb_err}")
    except Exception as e:
        print(f"Unexpected error during anomaly check orchestration for user {user_id}: {e}")
        # Potentially rollback here too if db_connection is valid and an error occurred that might leave transaction open
    finally:
        if cursor:
            cursor.close()

    print(f"User anomaly check orchestration completed for user {user_id}. Anomalies found: {anomalies_found_count}, Anomalies logged: {anomalies_logged_count}")
    
    # After logging, check if user needs to be blacklisted based on accumulated anomalies
    if anomalies_found_count > 0 : # or specifically if anomalies_logged_count > 0
        # This check_and_blacklist_user_if_needed should ideally be called by the main application flow
        # after run_all_user_anomaly_checks_and_log completes and returns its findings.
        # Calling it here makes this function have side effects beyond just checking and logging.
        # For now, as per existing structure, let's assume it's called here.
        # It needs its own transaction management or to be part of a larger one.
        # The current check_and_blacklist_user_if_needed handles its own connection if not passed.
        # It's better if it uses the passed db_connection.
        
        # For now, let's call it as it is, assuming it might open its own connection or be passed one.
        # If it's to use the *same* transaction, the design needs care.
        # The current `check_and_blacklist_user_if_needed` gets a new connection if one isn't passed or is None.
        # This means its blacklisting action will be in a separate transaction from the anomaly logging commit above.
        # This is generally acceptable: log anomalies, then separately check and blacklist.
        
        # No, check_and_blacklist_user_if_needed takes db_connection.
        # So it will use the same connection.
        # If anomalies were committed above, this function will operate on that committed state.
        try:
            print(f"Checking if user {user_id} needs blacklisting due to {anomalies_found_count} anomalies found.")
            blacklist_result = check_and_blacklist_user_if_needed(db_connection, user_id)
            if blacklist_result.get('blacklisted'):
                print(f"User {user_id} was blacklisted: {blacklist_result.get('message')}")
            elif blacklist_result.get('checked'):
                print(f"User {user_id} blacklisting check done: {blacklist_result.get('message')}")

        except Exception as e_blacklist_check:
            print(f"Error during check_and_blacklist_user_if_needed for user {user_id}: {e_blacklist_check}")


    return {'total_anomalies_found': anomalies_found_count, 'anomalies_logged': anomalies_logged_count}


# Example usage (illustrative, typically called from app.py or similar)
if __name__ == "__main__":
    conn = None
    try:
        # Get a database connection
        conn = get_db_connection() # Assumes get_db_connection is robust
        if not conn:
            print("Failed to get DB connection. Exiting example.")
            exit()

        # --- Test run_all_user_anomaly_checks_and_log ---
        print("\n--- Testing User Anomaly Orchestrator ---")
        # Ensure you have a user with ID 1 and role 'buyer' in your DB for this test
        # or change user_id_to_test and user_role_to_test accordingly.
        # Seed data might be needed for login_attempts, Order, cart_events, CustomerSupport, Review tables.
        user_id_to_test = 1 
        user_role_to_test = 'buyer' # Test with 'buyer', 'seller'
        
        print(f"Running anomaly checks for user_id: {user_id_to_test}, role: {user_role_to_test}")
        orchestrator_results = run_all_user_anomaly_checks_and_log(conn, user_id_to_test, user_role_to_test)
        print(f"Orchestrator results for user {user_id_to_test}: {orchestrator_results}")

        # --- Test count_user_anomalies ---
        # This function is now implicitly tested by check_and_blacklist_user_if_needed
        # but can be tested directly if needed.
        # anomalies = count_user_anomalies(conn.cursor(), user_id_to_test) # Assuming cursor needed
        # print(f"User {user_id_to_test} has {anomalies} anomalies logged in detected_anomalies.")
        
        # --- Test automatic blacklisting (if anomalies were logged) ---
        # The orchestrator now calls check_and_blacklist_user_if_needed
        # blacklist_status = check_and_blacklist_user_if_needed(conn, user_id_to_test)
        # print(f"Blacklist check for user {user_id_to_test}: {blacklist_status}")

        # --- Test manual blacklisting ---
        # print("\n--- Testing Manual Blacklisting ---")
        # admin_performing_blacklist = 100 # Example admin user ID
        # user_to_blacklist_email = "charlie.brown@example.com" # Ensure this user exists and is not admin
        
        # # Create a dummy user to blacklist if they don't exist (for testing)
        # # Make sure this user is not an admin and not already blacklisted.
        # # Example: (You would run this SQL in your DB client or a setup script)
        # # INSERT INTO User (username, email, password_hash, role, status)
        # # VALUES ('charliebrown', 'charlie.brown@example.com', 'somehash', 'buyer', 'active')
        # # ON DUPLICATE KEY UPDATE status = IF(status='blacklisted', 'blacklisted', 'active'); -- be careful with this
        
        # manual_blacklist_result = manually_blacklist_user_by_email(conn, user_to_blacklist_email, admin_performing_blacklist, "Manual review identified suspicious activity.")
        # print(f"Manual blacklist result for {user_to_blacklist_email}: {manual_blacklist_result}")

        # # Verify: Check User table status and blacklisted_users table for this user.

    except mysql.connector.Error as e:
        print(f"Database error in main example: {e}")
    except Exception as e:
        print(f"An unexpected error occurred in main example: {e}")
    finally:
        if conn and conn.is_connected():
            conn.close()
            print("Database connection closed.")


def count_user_anomalies(db_cursor, user_id):
    """
    Counts the number of distinct anomaly types logged for a user in the detected_anomalies table.
    Uses the passed db_cursor. Does not commit or rollback.
    """
    if not db_cursor:
        print("Error: DB cursor not provided to count_user_anomalies.")
        return 0 
        
    try:
        # Count distinct anomaly_type to avoid over-counting if the same type is logged multiple times
        # (though current logging seems to log once per detection event)
        # If we want to count every single logged row, remove DISTINCT.
        query = "SELECT COUNT(DISTINCT anomaly_type) FROM detected_anomalies WHERE user_id = %s"
        # If we want to count all logged rows:
        # query = "SELECT COUNT(*) FROM detected_anomalies WHERE user_id = %s"
        
        db_cursor.execute(query, (user_id,))
        result = db_cursor.fetchone()
        return result[0] if result else 0
    except mysql.connector.Error as e:
        print(f"Error counting anomalies for user {user_id}: {e}")
        return 0 # Return 0 on error to prevent unintended actions based on error

def blacklist_user(db_connection, user_id, reason="accumulated_2_anomalies"):
    """
    Blacklists a user:
    1. Copies their details to the blacklisted_users table.
    2. Updates their status to 'blacklisted' and NULLs their password_hash in the User table.
    Manages its own transaction.
    """
    if not db_connection:
        print(f"Error: DB connection not provided to blacklist_user for user_id {user_id}.")
        return {'success': False, 'message': 'DB connection error.'}

    cursor = None
    try:
        cursor = db_connection.cursor()

        # 1. Fetch user details to copy
        cursor.execute("SELECT email, password_hash, role FROM User WHERE id = %s", (user_id,))
        user_to_blacklist = cursor.fetchone()

        if not user_to_blacklist:
            return {'success': False, 'message': f'User with ID {user_id} not found for blacklisting.'}

        email, current_password_hash, original_role = user_to_blacklist

        # Check if already blacklisted (in User table)
        cursor.execute("SELECT status FROM User WHERE id = %s", (user_id,))
        current_status = cursor.fetchone()[0]
        if current_status == 'blacklisted':
            # Optional: Could also check blacklisted_users table if User table might be out of sync.
            return {'success': True, 'message': f'User {user_id} is already blacklisted (status in User table).'}


        # 2. Insert into blacklisted_users table
        # Assuming blacklisted_by_admin_id is NULL for automated blacklisting, or a system user ID.
        # For this generic function, let's assume NULL or a system ID if available.
        # The new manual function will provide admin_user_id.
        # Here, for automated, let's use NULL for blacklisted_by_admin_id.
        insert_query = """
        INSERT INTO blacklisted_users (user_id, email, password_hash, original_role, reason, blacklisted_by_admin_id, blacklist_timestamp)
        VALUES (%s, %s, %s, %s, %s, NULL, %s)
        """
        # blacklist_timestamp is set by the database default (CURRENT_TIMESTAMP) or can be set here.
        # Let's set it explicitly.
        blacklist_timestamp_time = datetime.datetime.now()
        cursor.execute(insert_query, (user_id, email, current_password_hash, original_role, reason, blacklist_timestamp_time))

        # 3. Update User table: set status to 'blacklisted' and password_hash to NULL
        update_query = "UPDATE User SET status = 'blacklisted', password_hash = NULL WHERE id = %s"
        cursor.execute(update_query, (user_id,))

        db_connection.commit()
        
        # Log this blacklisting action
        # Assuming a system user ID for automated actions, or pass if available.
        # For now, using user_id as reference_id for log_activity.
        log_activity(db_connection, user_id, 'user_blacklisted_auto', f'User {user_id} ({email}) automatically blacklisted. Reason: {reason}', commit_now=True) # commit_now=True as this is a final action.

        print(f"User {user_id} ({email}) successfully blacklisted. Reason: {reason}")
        return {'success': True, 'message': f'User {user_id} successfully blacklisted. Reason: {reason}'}

    except mysql.connector.Error as e:
        print(f"Database error during blacklisting user {user_id}: {e}")
        if db_connection:
            try:
                db_connection.rollback()
            except mysql.connector.Error as rb_err:
                print(f"Error during rollback for blacklist_user: {rb_err}")
        return {'success': False, 'message': f'Database error: {e}'}
    except Exception as e_gen:
        print(f"Unexpected error during blacklisting user {user_id}: {e_gen}")
        if db_connection: # Ensure rollback on any exception if transaction might be open
            try:
                db_connection.rollback()
            except mysql.connector.Error as rb_err:
                print(f"Error during rollback for blacklist_user (general exception): {rb_err}")
        return {'success': False, 'message': f'Unexpected error: {e_gen}'}
    finally:
        if cursor:
            cursor.close()

def manually_blacklist_user_by_email(db_connection, target_email, admin_user_id, manual_reason):
    print(f"[MEGA_DEBUG_V1] MANUALLY_BLACKLIST_USER_BY_EMAIL FUNCTION ENTERED for {target_email}") # New function-level print
    print(f"[DEBUG_CACHE_BUSTER_V3] Entering manually_blacklist_user_by_email for {target_email}")
    """
    Manually blacklists a user based on their email address.
    Operates within a database transaction.
    - Fetches user details by email.
    - Validates if the user can be blacklisted (not admin, not already blacklisted).
    - Inserts user details into 'blacklisted_users' table.
    - Updates user's status to 'blacklisted' and NULLs password_hash in 'User' table.
    - Logs the manual blacklisting action.
    Returns a dictionary {'success': bool, 'message': str}.
    """
    cursor = None
    try:
        cursor = db_connection.cursor() # Using standard tuple-based results

        # Fetch User Details: id, role, password_hash, status
        query_fetch_user = "SELECT id, role, password_hash, status FROM User WHERE email = %s"
        cursor.execute(query_fetch_user, (target_email,))
        user_data = cursor.fetchone()

        if not user_data:
            print(f"Error: User with email {target_email} not found for manual blacklisting.")
            # No transaction started that needs explicit rollback for this path if only SELECT failed
            return {'success': False, 'message': f'User with email {target_email} not found.'}

        user_id_to_blacklist = user_data[0]
        user_role = user_data[1]
        user_password_hash = user_data[2] # This is the original password hash to store
        user_status = user_data[3]

        # Validation
        if user_role == 'admin':
            print(f"Error: Admin user {target_email} (ID: {user_id_to_blacklist}) cannot be manually blacklisted.")
            return {'success': False, 'message': 'Admin users cannot be blacklisted.'}

        if user_status == 'blacklisted':
            print(f"Info: User {target_email} (ID: {user_id_to_blacklist}) is already blacklisted.")
            # Check if entry exists in blacklisted_users for completeness, though User.status is primary
            # For now, this check is sufficient as per instructions.
            return {'success': False, 'message': f'User {target_email} is already blacklisted.'}

        # Blacklisting Process
        # 1. Insert into blacklisted_users table
        query_insert_blacklisted = """
        INSERT INTO blacklisted_users
            (user_id, email, password_hash, original_role, reason, blacklisted_by_admin_id, blacklist_timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        current_timestamp = datetime.datetime.now()
        cursor.execute(query_insert_blacklisted, (
            user_id_to_blacklist,
            target_email,
            user_password_hash, # Store the original hash
            user_role,
            manual_reason,
            admin_user_id,
            current_timestamp
        ))

        # 2. Update User Table: set status to 'blacklisted' and password_hash to NULL
        print(f"[DEBUG] manually_blacklist_user_by_email: Attempting to update User table for user_id: {user_id_to_blacklist} to set status='blacklisted' and password_hash=NULL")
        query_update_user = "UPDATE User SET status = 'blacklisted', password_hash = NULL WHERE id = %s"
        cursor.execute(query_update_user, (user_id_to_blacklist,))
        print(f"[DEBUG] manually_blacklist_user_by_email: Rows affected by User table update for user_id {user_id_to_blacklist}: {cursor.rowcount}")

        # Commit the transaction
        print(f"[DEBUG] manually_blacklist_user_by_email: Attempting to commit transaction for blacklisting user_id: {user_id_to_blacklist}")
        db_connection.commit()
        print(f"[DEBUG] manually_blacklist_user_by_email: Transaction committed for blacklisting user_id: {user_id_to_blacklist}")

        # Log activity for the manual blacklist action
        log_activity(
            db_connection,
            admin_user_id, # The admin performing the action
            'manual_blacklist_user',
            f'Admin {admin_user_id} blacklisted user {target_email} (ID: {user_id_to_blacklist}). Reason: {manual_reason}',
            commit_now=True # As per instruction, ensures this log is committed.
        )
        
        print(f"User {target_email} (ID: {user_id_to_blacklist}) successfully blacklisted by admin {admin_user_id}.")
        return {'success': True, 'message': f'User {target_email} successfully blacklisted by admin {admin_user_id}.'}

    except mysql.connector.Error as err:
        print(f"Database error during manual blacklisting of {target_email}: {err}")
        if db_connection:
            try:
                db_connection.rollback()
            except mysql.connector.Error as rb_err:
                print(f"Error during rollback after database error: {rb_err}")
        return {'success': False, 'message': 'A database error occurred during the manual blacklisting process.'}
    except Exception as e: # Catch any other unexpected errors
        print(f"Unexpected error during manual blacklisting of {target_email}: {e}")
        if db_connection:
            try:
                db_connection.rollback()
            except mysql.connector.Error as rb_err:
                print(f"Error during rollback after unexpected error: {rb_err}")
        return {'success': False, 'message': f'An unexpected error occurred: {str(e)}'}
    finally:
        if cursor:
            cursor.close()

def check_and_blacklist_user_if_needed(db_connection, user_id):
    """
    Checks if a user has accumulated 2 or more distinct anomalies and blacklists them if so.
    This function now uses the passed db_connection.
    It manages its own transaction for counting and potentially blacklisting.
    """
    # ANOMALY_THRESHOLD_FOR_BLACKLIST = 2 # Defined as 2 in problem, can be configurable
    ANOMALY_THRESHOLD_FOR_BLACKLIST = 2 

    if not db_connection:
        print(f"Error: DB connection not provided to check_and_blacklist_user for user_id {user_id}.")
        # Or, could try to get a new one if that's the desired behavior for standalone use.
        # For now, require it.
        return {'checked': False, 'blacklisted': False, 'message': 'DB connection error.'}

    cursor = None
    try:
        # This function will perform a SELECT (count) and potentially DML (blacklist_user call).
        # It should manage its transaction carefully.
        # The blacklist_user function itself manages its own transaction.
        # So, this function primarily needs a cursor for counting.
        
        cursor = db_connection.cursor()
        
        # First, check if user is already blacklisted to avoid redundant checks/logging
        cursor.execute("SELECT status FROM User WHERE id = %s", (user_id,))
        user_status_result = cursor.fetchone()
        if user_status_result and user_status_result[0] == 'blacklisted':
            return {'checked': True, 'blacklisted': True, 'message': f'User {user_id} is already blacklisted.'}

        num_anomalies = count_user_anomalies(cursor, user_id) # count_user_anomalies uses the passed cursor
        
        print(f"User {user_id} has {num_anomalies} distinct anomalies logged.")

        if num_anomalies >= ANOMALY_THRESHOLD_FOR_BLACKLIST:
            print(f"User {user_id} reached anomaly threshold ({num_anomalies}/{ANOMALY_THRESHOLD_FOR_BLACKLIST}). Initiating blacklisting.")
            # blacklist_user manages its own transaction, using the same db_connection
            blacklist_result = blacklist_user(db_connection, user_id, reason=f"accumulated_{num_anomalies}_anomalies")
            return {
                'checked': True, 
                'blacklisted': blacklist_result.get('success', False), 
                'message': blacklist_result.get('message', 'Blacklisting process completed.')
            }
        else:
            return {'checked': True, 'blacklisted': False, 'message': f'User {user_id} has {num_anomalies} anomalies, below threshold of {ANOMALY_THRESHOLD_FOR_BLACKLIST}.'}

    except mysql.connector.Error as e:
        # No rollback needed here typically if only SELECTs failed or if blacklist_user handles its own rollback.
        print(f"Database error in check_and_blacklist_user_if_needed for user {user_id}: {e}")
        return {'checked': False, 'blacklisted': False, 'message': f'Database error: {e}'}
    except Exception as e_gen:
        print(f"Unexpected error in check_and_blacklist_user_if_needed for user {user_id}: {e_gen}")
        return {'checked': False, 'blacklisted': False, 'message': f'Unexpected error: {e_gen}'}
    finally:
        if cursor:
            cursor.close()