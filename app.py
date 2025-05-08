import streamlit as st
import mysql.connector
import os
from dotenv import load_dotenv
import bcrypt
import pandas as pd
from datetime import datetime, date # Added date for blacklist duration
from utils import log_activity, check_blacklist, get_db_connection, get_all_reviews, get_all_customer_tickets, get_detected_anomalies # Moved get_db_connection here for consistency
from fraud_detection import run_fraud_checks, run_all_user_anomaly_checks_and_log, check_and_blacklist_user_if_needed, count_user_anomalies, manually_blacklist_user_by_email, blacklist_user # Import fraud detection functions
import time # For timed messages

# Load environment variables from .env file
load_dotenv()

# Handle timed blacklist message display
if 'show_blacklisted_message_duration' in st.session_state:
    if st.session_state.show_blacklisted_message_duration > 0:
        st.error("YOU ARE BLACKLISTED FOR ATTEMPTING TO FRAUD! This message will disappear after a few interactions.")
        st.session_state.show_blacklisted_message_duration -= 1
    # Check if duration became <= 0 after decrementing, or if it was already <= 0
    if 'show_blacklisted_message_duration' in st.session_state and st.session_state.show_blacklisted_message_duration <= 0:
        del st.session_state['show_blacklisted_message_duration']

# Database Connection Function
# Moved get_db_connection to utils.py for central management
# Ensure it's imported correctly: from utils import get_db_connection

# --- Authentication Function ---
def login_user(email, password):
    """Verifies user credentials against the database."""
    conn = get_db_connection()
    if not conn:
        return None, None
    
    user = None
    role = None
    try:
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT id, password_hash, role FROM User WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            if user_data:
                # Verify password
                stored_hash = user_data['password_hash']
                if stored_hash is None:
                    # Password hash is NULL, likely blacklisted user
                    return None, "blacklisted" # Indicate blacklisted status

                # Ensure both are bytes for bcrypt
                if isinstance(stored_hash, str):
                    stored_hash = stored_hash.encode('utf-8')
                
                # It's possible bcrypt.checkpw could still fail if stored_hash is an empty string after encode
                # but our primary concern here is None.
                if stored_hash and bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    user = user_data['id']
                    role = user_data['role']
    except mysql.connector.Error as err:
        st.error(f"Database error during login: {err}")
    finally:
        if conn and conn.is_connected():
            conn.close() # Close connection after use
    return user, role

# Basic Page Configuration
st.set_page_config(page_title="E-com Detectify", layout="wide")
# Custom CSS for theming
custom_theme_css = f"""
<style>
    :root {{
        --primary-color: red !important;
        --background-color: white !important;
        --secondary-background-color: white !important; /* For elements like cards, sidebars */
        --text-color: black !important;
        --font: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
    }}

    body, .stApp, .main {{ /* Apply to body and main Streamlit app container */
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: black !important;
        background-color: white !important; /* Ensure main background is white */
    }}

    /* Ensure all text elements inherit the font and color */
    h1, h2, h3, h4, h5, h6, p, div, span, label, li, a, th, td,
    .stTextInput label, .stTextArea label, .stSelectbox label, .stDateInput label, .stNumberInput label, .stRadio label, .stCheckbox label,
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] > div,
    .stDateInput input, .stNumberInput input,
    .stMetric, .stMetric label, .stMetric div[data-testid="stMetricValue"],
    .stDataFrame {{
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: black !important;
    }}

    /* Buttons */
    .stButton > button {{
        background-color: red !important;
        color: white !important; /* Text on red buttons */
        border: 1px solid red !important;
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
    }}
    .stButton > button:hover {{
        background-color: darkred !important;
        border-color: darkred !important;
        color: white !important;
    }}
    .stButton > button:active {{
        background-color: #b20000 !important; /* Even darker red for active state */
        border-color: #b20000 !important;
        color: white !important;
    }}
    .stButton > button:focus {{
        box-shadow: 0 0 0 0.2rem rgba(255, 0, 0, 0.5) !important;
    }}

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {{
        background-color: white !important;
    }}
    .stTabs [data-baseweb="tab"] {{
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: #555 !important; /* Default tab text color */
        background-color: #f0f2f6 !important; /* Default tab background */
    }}
    .stTabs [data-baseweb="tab"]:hover {{
        color: black !important;
        background-color: #e6e6e6 !important;
    }}
    .stTabs [data-baseweb="tab"][aria-selected="true"] {{
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: white !important; /* Text of active tab on red background */
        background-color: red !important; /* Active tab background */
        border-bottom-color: red !important; 
        box-shadow: none !important;
    }}
    .stTabs [data-baseweb="tab"][aria-selected="true"] > div {{
         color: white !important; /* Ensure text within the active tab div is white */
    }}

    /* Markdown specific styling */
    .stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6, .stMarkdown strong, .stMarkdown em, .stMarkdown code, .stMarkdown pre {{
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: black !important;
    }}

    /* Input fields styling */
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] > div, .stDateInput input, .stNumberInput input {{
        border-color: #ccc !important; /* A neutral border for inputs */
    }}
    .stTextInput input:focus, .stTextArea textarea:focus, .stSelectbox div[data-baseweb="select"]:focus-within, .stDateInput input:focus, .stNumberInput input:focus {{
        border-color: red !important; /* Primary color border on focus */
        box-shadow: 0 0 0 0.2rem rgba(255, 0, 0, 0.25) !important;
    }}

    /* Sidebar styling if it exists and needs to be white */
    [data-testid="stSidebar"] {{
        background-color: white !important;
    }}
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3, [data-testid="stSidebar"] p, [data-testid="stSidebar"] div, [data-testid="stSidebar"] span, [data-testid="stSidebar"] label, [data-testid="stSidebar"] li, [data-testid="stSidebar"] a {{
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: black !important;
    }}

</style>
"""
# st.markdown(custom_theme_css, unsafe_allow_html=True)

# Initialize session state variables if they don't exist
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'role' not in st.session_state:
    st.session_state.role = None

# --- Sidebar Placeholder ---

# --- Main Page Content ---
if st.session_state.logged_in:
    # Create columns for alignment, logout button on the top-right
    # Using a large ratio for the first column to push the button to the far right
    _, logout_button_col = st.columns([10, 1]) # Adjust ratio for desired spacing
    with logout_button_col:
        if st.button("Logout", key="main_logout_button_top_right"): # Added a unique key
            conn = get_db_connection()
            if conn and st.session_state.user_id:
                log_activity(conn, st.session_state.user_id, 'logout')
                if conn.is_connected():
                    conn.close()
            # Logout logic
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.role = None
            st.rerun() # Rerun to reflect logout state

st.markdown("<h1 style='text-align: center;'>E-com Detectify</h1>", unsafe_allow_html=True)

if not st.session_state.logged_in:
    st.markdown("<h2 style='text-align: center;'>Login</h2>", unsafe_allow_html=True)
    
    # Center the login form
    login_col_left, login_col_center, login_col_right = st.columns([1, 1.5, 1]) # Adjust ratios as needed for desired width
    with login_col_center:
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            
            if submitted:
                user_id, role = login_user(email, password)

                if role == "blacklisted":
                    st.error("User is Blacklisted. Access Denied!")
                elif user_id:
                    db_conn_pre_check = None
                    cursor_pre_check = None
                    perform_login_steps = True # Flag to control login progression

                    try:
                        db_conn_pre_check = get_db_connection()
                        if not db_conn_pre_check:
                            st.error("Database connection failed (pre-check). Please try again.")
                            perform_login_steps = False
                        else:
                            cursor_pre_check = db_conn_pre_check.cursor(dictionary=True)
                            cursor_pre_check.execute("SELECT status FROM User WHERE id = %s", (user_id,))
                            user_status_details = cursor_pre_check.fetchone()

                            if user_status_details and user_status_details['status'] == 'blacklisted':
                                st.error("Your account has been suspended due to suspicious activity. Please contact support.")
                                perform_login_steps = False
                        
                    except mysql.connector.Error as e_pre_check_db:
                        st.error(f"Database error during pre-login check: {e_pre_check_db}")
                        perform_login_steps = False
                        print(f"Error during pre_login_check DB: {e_pre_check_db}")
                    except Exception as e_pre_check_generic:
                        st.error(f"An unexpected error occurred during pre-login check: {e_pre_check_generic}")
                        perform_login_steps = False
                        print(f"Error during pre_login_check_generic: {e_pre_check_generic}")
                    finally:
                        if cursor_pre_check:
                            cursor_pre_check.close()
                        if db_conn_pre_check and db_conn_pre_check.is_connected():
                            db_conn_pre_check.close()

                    if perform_login_steps:
                        st.session_state.logged_in = True
                        st.session_state.user_id = user_id
                        st.session_state.role = role

                        conn_post_login = None
                        try:
                            conn_post_login = get_db_connection()
                            if not conn_post_login:
                                st.warning("Could not establish connection for post-login checks. Login proceeded but some checks might be skipped.")
                                log_activity(None, user_id, 'login_warning_no_db_for_post_checks') # Log warning
                            else:
                                log_activity(conn_post_login, user_id, 'login')

                                current_user_id_for_checks = st.session_state.user_id
                                current_user_role_for_checks = st.session_state.role

                                print(f"Running post-login anomaly checks for user: {current_user_id_for_checks}")
                                run_all_user_anomaly_checks_and_log(conn_post_login, current_user_id_for_checks, current_user_role_for_checks)
                                
                                print(f"Running post-login blacklist check for user: {current_user_id_for_checks}")
                                blacklist_result = check_and_blacklist_user_if_needed(conn_post_login, current_user_id_for_checks)
                                
                                if blacklist_result.get('blacklisted'):
                                    st.error("YOU ARE BLACKLISTED FOR ATTEMPTING TO FRAUD!")
                                    keys_to_del_on_blacklist = [k for k in st.session_state.keys() if k not in ['show_blacklisted_message_duration']]
                                    for k_del in keys_to_del_on_blacklist:
                                        del st.session_state[k_del]
                                    st.session_state.logged_in = False
                                    st.session_state.show_blacklisted_message_duration = 5
                                    # No st.rerun() here, it will be handled by the final rerun outside this block if not blacklisted
                                    # or by the immediate rerun after this 'if' block if blacklisted.
                                    perform_login_steps = False # Mark that full login sequence (including final rerun) should not occur as user is now logged out.
                                    st.rerun() # Rerun immediately to reflect blacklist and logout
                                    # This st.rerun() is crucial for immediate effect of blacklisting.

                        except mysql.connector.Error as e_post_login_db:
                            st.error(f"Database error during post-login checks: {e_post_login_db}")
                            print(f"Error during post_login_check DB: {e_post_login_db}")
                            # Log this error but don't necessarily block the user if login itself was fine before this point
                        except Exception as e_post_login_generic:
                            st.error(f"An unexpected error occurred during post-login checks: {e_post_login_generic}")
                            print(f"Error during post_login_check_generic: {e_post_login_generic}")
                        finally:
                            if conn_post_login and conn_post_login.is_connected():
                                conn_post_login.close()
                        
                        # This rerun happens if user was not blacklisted pre-login, and not blacklisted post-login.
                        if perform_login_steps: # Check flag again, as it might be set to False by post-login blacklisting
                           st.rerun()
                    # If perform_login_steps is False (due to pre-login blacklist or other pre-login error),
                    # no st.rerun() happens here, allowing error messages to be displayed on the current page.
                    # If blacklisted post-login, an st.rerun() already happened.

                else: # This 'else' corresponds to 'if user_id:'
                    st.error("Invalid email or password")
else:
    # --- Role-Based Dashboards ---
    if st.session_state.role == 'admin':
        # --- Admin Dashboard ---

        # --- Helper Functions (Scoped to Admin) ---

        @st.cache_data(ttl=30) # Cache balance for 30 seconds
        def get_wallet_balance(_conn, user_id):
            """Queries Wallet table for a specific user, returns balance_cents."""
            balance = 0
            cursor = None
            try:
                cursor = _conn.cursor(dictionary=True)
                cursor.execute("SELECT balance_cents FROM Wallet WHERE user_id = %s", (user_id,))
                result = cursor.fetchone()
                if result:
                    balance = result['balance_cents']
            except mysql.connector.Error as err:
                st.error(f"Error fetching wallet balance for user {user_id}: {err}")
            finally:
                if cursor:
                    cursor.close()
            return balance

        def update_wallet_balance(_conn, user_id, amount_change_cents):
            """Updates Wallet balance by adding/subtracting amount_change_cents."""
            cursor = None
            try:
                cursor = _conn.cursor()
                # Check if wallet exists, create if not (optional, depends on schema setup)
                # cursor.execute("INSERT IGNORE INTO Wallet (user_id, balance_cents) VALUES (%s, 0)", (user_id,))
                cursor.execute(
                    "UPDATE Wallet SET balance_cents = balance_cents + %s WHERE user_id = %s",
                    (amount_change_cents, user_id)
                )
                # Check if the update actually changed rows, handle if user doesn't exist?
                if cursor.rowcount == 0:
                     # Wallet not found, so create it with the initial adjustment amount
                     cursor.execute("INSERT INTO Wallet (user_id, balance_cents) VALUES (%s, %s)", (user_id, amount_change_cents))
                     # st.info(f"New wallet created for User ID {user_id} with balance: {amount_change_cents / 100:.2f}") # Optional info message
                # No commit here, assuming it's part of a larger transaction handled by the caller
                return True
            except mysql.connector.Error as err:
                st.error(f"Error updating wallet balance for user {user_id}: {err}")
                return False
            finally:
                if cursor:
                    cursor.close()

        @st.cache_data(ttl=120) # Cache counts for 2 minutes
        def get_count(_conn, table_name, condition="1=1"):
            """Gets the count of rows in a table, optionally with a condition."""
            count = 0
            cursor = None
            try:
                cursor = _conn.cursor(dictionary=True)
                # Basic sanitization: Ensure table_name is alphanumeric/underscore
                # More robust sanitization might be needed depending on usage
                safe_table_name = "".join(c for c in table_name if c.isalnum() or c == '_' or c == '`')
                if safe_table_name != table_name:
                     raise ValueError("Invalid table name format detected.")
                # Use placeholder for condition if it's complex, otherwise format carefully
                # For this specific use case, direct formatting is acceptable but be cautious
                query = f"SELECT COUNT(*) as count FROM {safe_table_name} WHERE {condition}"
                cursor.execute(query)
                result = cursor.fetchone()
                if result:
                    count = result['count']
            except (mysql.connector.Error, ValueError) as err:
                st.error(f"Error getting count for {table_name}: {err}")
            finally:
                if cursor:
                    cursor.close()
            return count

        @st.cache_data(ttl=60)
        def get_all_users(_conn):
            """Fetches all users."""
            users = []
            cursor = None
            try:
                cursor = _conn.cursor(dictionary=True)
                query = "SELECT id, email, role, created_at FROM User ORDER BY created_at DESC"
                cursor.execute(query)
                users = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching users: {err}")
            finally:
                if cursor:
                    cursor.close()
            return users

        @st.cache_data(ttl=30)
        def get_all_logs(_conn, limit=100):
            """Fetches recent activity logs, joining with User table."""
            logs = []
            cursor = None
            try:
                cursor = _conn.cursor(dictionary=True)
                query = """
                    SELECT l.id, l.timestamp, l.user_id, u.email as user_email, l.action, l.details
                    FROM activity_log l
                    LEFT JOIN User u ON l.user_id = u.id
                    ORDER BY l.timestamp DESC
                    LIMIT %s
                """
                cursor.execute(query, (limit,))
                logs = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching activity logs: {err}")
            finally:
                if cursor:
                    cursor.close()
            return logs

        # --- Admin Dashboard Main Logic ---

        # 1. Blacklist Check (Self)
        conn_admin_init = None
        is_blacklisted = False
        try:
            conn_admin_init = get_db_connection()
            if not conn_admin_init:
                st.error("Database connection failed. Cannot load Admin Dashboard.")
                st.stop()

            is_blacklisted = check_blacklist(conn_admin_init, st.session_state.user_id)

        except mysql.connector.Error as err:
            st.error(f"Error checking admin blacklist status: {err}")
            st.stop() # Stop if we cannot verify status
        finally:
            if conn_admin_init and conn_admin_init.is_connected():
                conn_admin_init.close()

        if is_blacklisted:
            st.error("Your admin account is currently blacklisted. Access denied.")
            log_activity(get_db_connection(), st.session_state.user_id, 'admin_blacklist_block', 'Admin attempted access while blacklisted') # Log attempt
            st.stop()

        st.title("Admin Dashboard")

        # 2. Tabs
        admin_tab_names = [
            "Overview", "User Management", "Create User", "Wallet Management",
            "Activity Log", "Anomaly Log", "All Reviews", "All Customer Tickets",
            "Manual User Blacklist", "View Anomaly Logs" # New tab
        ]
        tab_overview, tab_users, tab_create_user, tab_wallet, \
        tab_activity, tab_anomaly, tab_all_reviews, tab_all_tickets, \
        tab_manual_blacklist, tab_view_anomaly_logs = st.tabs(admin_tab_names)

        # Fetch data needed across multiple tabs once
        conn_tabs = get_db_connection()
        if not conn_tabs:
             st.error("Failed to connect to database for dashboard data.")
             st.stop()

        all_users_data = get_all_users(conn_tabs)
        users_df = pd.DataFrame(all_users_data) if all_users_data else pd.DataFrame(columns=['id', 'email', 'role', 'created_at'])

        # --- Overview Tab ---
        with tab_overview:
            st.subheader("Recent Anomaly Alerts")
            # Use the imported get_detected_anomalies from utils.py
            recent_anomalies = get_detected_anomalies(conn_tabs, limit=10)
            if recent_anomalies:
                # Ensure the DataFrame conversion handles the new column names from get_detected_anomalies
                df_recent_anomalies = pd.DataFrame(recent_anomalies)
                # Select and rename columns to match expected display if necessary, or adjust display logic
                # For now, displaying all columns returned by get_detected_anomalies
                st.dataframe(df_recent_anomalies, use_container_width=True)
            else:
                st.info("No recent anomalies detected.")

            st.divider()
            st.subheader("Platform Statistics")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Users", get_count(conn_tabs, "User"))
            with col2:
                st.metric("Total Products", get_count(conn_tabs, "Product"))
            with col3:
                 # Use backticks for reserved SQL keywords like Order
                st.metric("Total Orders", get_count(conn_tabs, "`Order`")) # Use backticks
            with col4:
                pending_reviews_count = 0
                try:
                    with conn_tabs.cursor(dictionary=True) as cursor:
                        query = """
                        SELECT COUNT(Review.id) AS review_count
                        FROM Review
                        JOIN User ON Review.buyer_id = User.id
                        WHERE User.status = 'active';
                        """
                        cursor.execute(query)
                        result = cursor.fetchone()
                        if result and 'review_count' in result:
                            pending_reviews_count = result['review_count']
                except Exception as e:
                    # Log this error appropriately in a real application
                    print(f"Error getting pending reviews count: {e}")
                st.metric("Pending Reviews", pending_reviews_count)

        # --- User Management Tab ---
        with tab_users:
            st.header("User Management")
            if not users_df.empty:
                # Add a 'Select' column for actions
                # users_df['Select'] = False # This creates a checkbox column, but might not be ideal for actions
                st.dataframe(users_df[['id', 'email', 'role', 'created_at']], use_container_width=True)

                st.subheader("Blacklist User")
                col1, col2 = st.columns([1, 2])
                with col1:
                    user_id_to_blacklist = st.selectbox(
                        "Select User ID to Blacklist/Unblacklist",
                        options=users_df['id'].tolist(),
                        key="user_id_blacklist_selectbox"
                    )
                with st.form("blacklist_form"):
                    action_type = st.radio("Action", ["Blacklist", "Unblacklist"], key="blacklist_action_radio")
                    reason = st.text_input("Reason (for blacklisting)", key="blacklist_reason_text")
                    submitted_blacklist = st.form_submit_button(f"{action_type} User")

                    if submitted_blacklist:
                        if action_type == "Blacklist" and not reason:
                            st.warning("Please provide a reason for blacklisting.")
                        else:
                            blacklist_conn = None
                            try:
                                blacklist_conn = get_db_connection()
                                if not blacklist_conn: raise Exception("DB connection failed")
                                cursor = blacklist_conn.cursor(dictionary=True) # Use dictionary cursor
                                if action_type == "Blacklist":
                                    # Fetch user's email to use with manually_blacklist_user_by_email
                                    cursor.execute("SELECT email FROM User WHERE id = %s", (user_id_to_blacklist,))
                                    user_data = cursor.fetchone()
                                    if user_data:
                                        target_email = user_data['email']
                                        admin_id = st.session_state.user_id # Assuming admin's ID is in session
                                        
                                        # Call the existing function from fraud_detection.py
                                        # This function handles setting User.status and inserting into blacklisted_users
                                        # It also handles its own commit/rollback within the function.
                                        # We pass the connection, but it might open its own if not careful.
                                        # For now, let's assume it uses the passed connection and cursor appropriately or handles its own.
                                        # The manually_blacklist_user_by_email function in fraud_detection.py
                                        # already commits or rolls back.
                                        
                                        # Re-checking manually_blacklist_user_by_email, it creates its own cursor
                                        # and commits. So we don't need to commit here for this path.
                                        # We also don't need the cursor from this scope for this specific call.
                                        
                                        # We need to ensure fraud_detection.manually_blacklist_user_by_email
                                        # uses the passed connection or we manage transactions carefully.
                                        # For simplicity, we'll let it manage its transaction.
                                        
                                        # The function `manually_blacklist_user_by_email` expects a connection,
                                        # target_email, admin_user_id, and manual_reason.
                                        # It will then find the user_id from the email.
                                        
                                        # Since we already have user_id_to_blacklist, it might be more direct
                                        # to call fraud_detection.blacklist_user if it were exposed and suitable,
                                        # or adapt the logic here.
                                        # fraud_detection.blacklist_user(conn, user_id, reason) looks suitable.

                                        # Let's use fraud_detection.blacklist_user directly
                                        
                                        # The blacklist_user function in fraud_detection.py handles the commit.
                                        # It takes (db_connection, user_id, reason)
                                        blacklist_user(blacklist_conn, user_id_to_blacklist, reason)
                                        # The blacklist_user function already logs activity.
                                        st.success(f"User ID {user_id_to_blacklist} ({target_email}) blacklisted. Reason: {reason}")
                                        # No explicit commit here as blacklist_user handles it.
                                    else:
                                        st.error(f"User ID {user_id_to_blacklist} not found.")
                                else: # Unblacklist
                                    # Update User status
                                    cursor.execute("UPDATE User SET status = 'active' WHERE id = %s", (user_id_to_blacklist,))
                                    # Remove from blacklisted_users table
                                    cursor.execute("DELETE FROM blacklisted_users WHERE user_id = %s", (user_id_to_blacklist,))
                                    blacklist_conn.commit() # Commit these changes
                                    log_activity(blacklist_conn, st.session_state.user_id, 'unblacklist_user', f'User ID: {user_id_to_blacklist}')
                                    st.success(f"User {user_id_to_blacklist} unblacklisted.")
                                
                                if cursor: # Close cursor if it was opened and used
                                    cursor.close()
                                st.cache_data.clear() # Clear user cache
                                st.rerun()
                            except mysql.connector.Error as err:
                                if blacklist_conn: blacklist_conn.rollback()
                                st.error(f"Database error: {err}")
                            except Exception as e:
                                st.error(f"Error: {e}")
                            finally:
                                if blacklist_conn and blacklist_conn.is_connected():
                                    blacklist_conn.close()
            else:
                st.info("No users found.")

        # --- Create User Tab ---
        with tab_create_user:
            st.header("Create New User")
            def get_next_user_number(conn_db, role_prefix_str):
                """Determines the next sequential number for a user based on role."""
                # Example: if role_prefix_str is "buyer", look for "buyer_1@example.com", "buyer_2@example.com", etc.
                # This is a simplified example; a robust solution might involve a separate sequence or more complex querying.
                cursor = None
                try:
                    cursor = conn_db.cursor(dictionary=True)
                    # A more robust way to get the max number from email
                    # This query assumes email format like 'prefix_number@example.com'
                    # It extracts the number part and finds the maximum.
                    # This is highly specific and might need adjustment based on actual email patterns.
                    # For simplicity, we'll use a basic count for now, but this is where you'd put more complex logic.
                    
                    # Simplified: Count existing users of that role and add 1
                    # This is NOT robust for generating unique emails if users can be deleted or emails change.
                    # query_count = "SELECT COUNT(*) as count FROM User WHERE role = %s"
                    # cursor.execute(query_count, (role_prefix_str,))
                    # count_result = cursor.fetchone()
                    # return (count_result['count'] + 1) if count_result else 1

                    # Attempt to find the highest number in existing emails for that role
                    # This is still a bit naive and depends on a strict naming convention.
                    query_max_num = f"SELECT email FROM User WHERE email LIKE '{role_prefix_str}\\_%@example.com'" # Escape underscore
                    cursor.execute(query_max_num)
                    existing_emails = cursor.fetchall()
                    max_num = 0
                    if existing_emails:
                        for row_email in existing_emails:
                            email_addr_str = row_email['email'] # Corrected: access by key
                            try:
                                # Extract number: e.g., "buyer_123@example.com" -> "123"
                                num_part = email_addr_str.split('@')[0].split('_')[-1]
                                if num_part.isdigit():
                                    max_num = max(max_num, int(num_part))
                            except Exception:
                                pass # Ignore if parsing fails for some email
                    return max_num + 1

                except mysql.connector.Error as e:
                    st.error(f"DB error getting next user number: {e}")
                    return 1 # Fallback
                finally:
                    if cursor:
                        cursor.close()

            with st.form("create_user_form", clear_on_submit=True):
                new_email_prefix = st.text_input("Email Prefix (e.g., testuser)", key="new_email_prefix")
                new_password = st.text_input("Password", type="password", key="new_password")
                new_role = st.selectbox("Role", ["buyer", "seller", "admin"], key="new_role_select")
                submitted_create = st.form_submit_button("Create User")

                if submitted_create:
                    if not new_email_prefix or not new_password:
                        st.warning("Please provide an email prefix and password.")
                    else:
                        conn_create_user = None
                        try:
                            conn_create_user = get_db_connection()
                            if not conn_create_user: raise Exception("DB connection failed for user creation")

                            # Determine next user number for the email
                            # This is a placeholder for a more robust unique email generation
                            # For example, you might query the DB for the highest existing number for that role.
                            # user_number = get_next_user_number(conn_create_user, new_role.lower())
                            # new_email = f"{new_email_prefix}_{user_number}@{os.getenv('DEFAULT_EMAIL_DOMAIN', 'example.com')}"
                            
                            # Simpler email generation for now, ensure it's unique
                            # This is still not guaranteed unique if run concurrently, needs DB constraint
                            timestamp_suffix = int(time.time() * 1000) # milliseconds for more uniqueness
                            new_email = f"{new_email_prefix}_{timestamp_suffix}@{os.getenv('DEFAULT_EMAIL_DOMAIN', 'example.com')}"


                            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                            
                            cursor = conn_create_user.cursor()
                            # Check if email already exists
                            cursor.execute("SELECT id FROM User WHERE email = %s", (new_email,))
                            if cursor.fetchone():
                                st.error(f"Email {new_email} already exists. Try a different prefix or wait a moment.")
                            else:
                                cursor.execute(
                                    "INSERT INTO User (email, password_hash, role) VALUES (%s, %s, %s)",
                                    (new_email, hashed_password.decode('utf-8'), new_role) # Store hash as string
                                )
                                new_user_id = cursor.lastrowid
                                conn_create_user.commit()
                                
                                # Log activity for user creation
                                log_activity(conn_create_user, st.session_state.user_id, 'create_user', f'New User ID: {new_user_id}, Email: {new_email}, Role: {new_role}')
                                
                                # Optionally, create a wallet for the new user
                                if new_role == 'buyer' or new_role == 'seller':
                                     cursor.execute("INSERT INTO Wallet (user_id, balance_cents) VALUES (%s, %s) ON DUPLICATE KEY UPDATE user_id=user_id", (new_user_id, 0)) # Ensure wallet exists, 0 balance
                                     conn_create_user.commit()

                                st.success(f"User {new_email} ({new_role}) created successfully with ID: {new_user_id}!")
                                st.cache_data.clear() # Clear user cache
                                # No st.rerun() needed due to clear_on_submit=True and form behavior
                            cursor.close()
                        except mysql.connector.Error as err:
                            if conn_create_user: conn_create_user.rollback()
                            st.error(f"Database error creating user: {err}")
                        except Exception as e:
                            st.error(f"Error creating user: {e}")
                        finally:
                            if conn_create_user and conn_create_user.is_connected():
                                conn_create_user.close()
        
        # --- Wallet Management Tab ---
        with tab_wallet:
            st.header("Wallet Management")
            if not users_df.empty:
                col1_wallet, col2_wallet = st.columns([1, 2])
                with col1_wallet:
                    selected_user_id_wallet = st.selectbox(
                        "Select User ID for Wallet",
                        options=users_df['id'].tolist(), # Show all users
                        key="user_id_wallet_select"
                    )
                    if selected_user_id_wallet:
                        current_balance_cents = get_wallet_balance(conn_tabs, selected_user_id_wallet)
                        st.metric(f"Current Balance for User {selected_user_id_wallet}", f"${current_balance_cents / 100:.2f}")

                with col2_wallet:
                    st.subheader("Adjust Wallet Balance")
                    with st.form("wallet_adjust_form"):
                        adjustment_amount_dollars = st.number_input("Adjustment Amount (USD)", value=0.0, step=0.01, format="%.2f", key="wallet_adj_amount")
                        adjustment_type = st.radio("Action", ["Add to Balance", "Subtract from Balance"], key="wallet_adj_type")
                        reason_wallet = st.text_input("Reason for adjustment", key="wallet_adj_reason")
                        submitted_wallet_adjust = st.form_submit_button("Adjust Balance")

                        if submitted_wallet_adjust:
                            if not reason_wallet:
                                st.warning("Please provide a reason for the wallet adjustment.")
                            elif selected_user_id_wallet:
                                adjustment_amount_cents = int(adjustment_amount_dollars * 100)
                                if adjustment_type == "Subtract from Balance":
                                    adjustment_amount_cents *= -1
                                
                                wallet_conn = None
                                try:
                                    wallet_conn = get_db_connection()
                                    if not wallet_conn: raise Exception("DB connection failed for wallet adjustment")

                                    success = update_wallet_balance(wallet_conn, selected_user_id_wallet, adjustment_amount_cents)
                                    if success:
                                        wallet_conn.commit()
                                        log_activity(wallet_conn, st.session_state.user_id, 'adjust_wallet', f'User ID: {selected_user_id_wallet}, Amount Cents: {adjustment_amount_cents}, Reason: {reason_wallet}')
                                        st.success(f"Wallet for User {selected_user_id_wallet} adjusted by ${adjustment_amount_dollars:.2f}.")
                                        st.cache_data.clear() # Clear wallet balance cache
                                        st.rerun() # Rerun to show updated balance
                                    else:
                                        st.error("Failed to update wallet balance (function returned false).")
                                        if wallet_conn: wallet_conn.rollback() # Rollback if update function indicated failure but didn't raise DB error

                                except mysql.connector.Error as err:
                                    if wallet_conn: wallet_conn.rollback()
                                    st.error(f"Database error adjusting wallet: {err}")
                                except Exception as e:
                                    st.error(f"Error adjusting wallet: {e}")
                                finally:
                                    if wallet_conn and wallet_conn.is_connected():
                                        wallet_conn.close()
                            else:
                                st.warning("Please select a user.")
            else:
                st.info("No users found to manage wallets.")


        # --- Activity Log Tab ---
        with tab_activity:
            st.header("Recent Activity Log")
            activity_logs = get_all_logs(conn_tabs, limit=200) # Fetch more logs
            if activity_logs:
                st.dataframe(pd.DataFrame(activity_logs), use_container_width=True)
            else:
                st.info("No activity logs found.")

        # --- Anomaly Log Tab ---
        with tab_anomaly:
            st.header("Anomaly Detection Log")
            # Use the imported get_detected_anomalies from utils.py
            anomaly_logs = get_detected_anomalies(conn_tabs, limit=200) # Fetch more anomalies
            if anomaly_logs:
                # Ensure the DataFrame conversion handles the new column names
                df_anomaly_logs = pd.DataFrame(anomaly_logs)
                # Display all columns returned by get_detected_anomalies
                st.dataframe(df_anomaly_logs, use_container_width=True)
            else:
                st.info("No anomalies detected.")
        
        # --- All Reviews Tab (Admin) ---
        with tab_all_reviews:
            st.header("All Product Reviews")
            all_reviews_data = get_all_reviews(conn_tabs) # Using the function from utils
            if all_reviews_data:
                reviews_df = pd.DataFrame(all_reviews_data)
                st.dataframe(reviews_df, use_container_width=True)
            else:
                st.info("No reviews found.")

        # --- All Customer Tickets Tab (Admin) ---
        with tab_all_tickets:
            st.header("All Customer Support Tickets")
            all_tickets_data = get_all_customer_tickets(conn_tabs) # Using the function from utils
            if all_tickets_data:
                tickets_df = pd.DataFrame(all_tickets_data)
                st.dataframe(tickets_df, use_container_width=True)
            else:
                st.info("No customer support tickets found.")

        # --- Manual User Blacklist Tab (Admin) ---
        with tab_manual_blacklist:
            st.subheader("Manually Blacklist a User")
            with st.form("manual_blacklist_form", clear_on_submit=True):
                st.write("Enter the details of the user to manually blacklist:")
                target_email_input = st.text_input("User's Email Address", key="manual_blacklist_email")
                manual_reason_input = st.text_area("Reason for Blacklisting", key="manual_blacklist_reason")
                submit_manual_blacklist = st.form_submit_button("Blacklist User")

                if submit_manual_blacklist:
                    if not target_email_input or not manual_reason_input:
                        st.warning("Please provide both email and reason.")
                    else:
                        admin_id = st.session_state.user_id # Admin performing the action
                        db_conn_manual_bl = None
                        try:
                            db_conn_manual_bl = get_db_connection()
                            if db_conn_manual_bl:
                                result = manually_blacklist_user_by_email(
                                    db_conn_manual_bl,
                                    target_email_input,
                                    admin_id,
                                    manual_reason_input
                                )
                                if result.get('success'):
                                    st.success(result.get('message'))
                                else:
                                    st.error(result.get('message'))
                            else:
                                st.error("Failed to connect to the database.")
                        except Exception as e_manual_bl:
                            st.error(f"An error occurred: {e_manual_bl}")
                            print(f"Error during manual blacklist form submission: {e_manual_bl}")
                        finally:
                            if db_conn_manual_bl and db_conn_manual_bl.is_connected():
                                db_conn_manual_bl.close()
        
# --- View Anomaly Logs Tab (Admin) ---
        with tab_view_anomaly_logs:
            st.subheader("Detected Anomaly Logs")
            db_conn_logs = None
            try:
                # Use the existing conn_tabs if it's still valid and open, otherwise get a new one.
                # However, for simplicity and to ensure a fresh connection for this specific task,
                # let's get a new connection. This also avoids issues if conn_tabs was closed earlier.
                db_conn_logs = get_db_connection()
                if db_conn_logs:
                    # Add a refresh button
                    if st.button("Refresh Anomaly Logs", key="refresh_detected_anomalies"):
                        st.cache_data.clear() # Clear cache if get_detected_anomalies uses caching
                        st.rerun()
                        
                    # Fetch logs using the imported function
                    # The get_detected_anomalies function is assumed to exist in utils.py
                    # and handle its own caching if necessary.
                    anomaly_logs = get_detected_anomalies(db_conn_logs, limit=200) 
                    
                    if anomaly_logs:
                        logs_df = pd.DataFrame(anomaly_logs)
                        # Optional: Format timestamp for better readability
                        if 'detection_timestamp' in logs_df.columns:
                            logs_df['detection_timestamp'] = pd.to_datetime(logs_df['detection_timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Display raw details string for now
                        st.dataframe(logs_df, use_container_width=True)
                    else:
                        st.info("No detected anomaly logs found.")
                else:
                    st.error("Failed to connect to the database to fetch anomaly logs.")
            except Exception as e_logs:
                st.error(f"An error occurred while fetching anomaly logs: {e_logs}")
                print(f"Error in View Anomaly Logs tab: {e_logs}")
            finally:
                if db_conn_logs and db_conn_logs.is_connected():
                    db_conn_logs.close()
        if conn_tabs and conn_tabs.is_connected(): # Close the connection for tabs if open
            conn_tabs.close()

    elif st.session_state.role == 'seller':
        # --- Seller Dashboard ---
        st.title("Seller Dashboard")
        conn_seller_init = get_db_connection() # Initial connection for blacklist check
        if not conn_seller_init:
            st.error("Database connection failed. Cannot load Seller Dashboard.")
            st.stop()

        is_blacklisted_seller = False
        try:
            is_blacklisted_seller = check_blacklist(conn_seller_init, st.session_state.user_id)
        except mysql.connector.Error as err:
            st.error(f"Error checking seller blacklist status: {err}")
            st.stop()
        finally:
            if conn_seller_init and conn_seller_init.is_connected():
                conn_seller_init.close()

        if is_blacklisted_seller:
            st.error("Your seller account is currently blacklisted. Access denied.")
            log_activity(get_db_connection(), st.session_state.user_id, 'seller_blacklist_block', 'Seller attempted access while blacklisted')
            st.stop()


        # --- Helper Functions (Scoped to Seller) ---
        @st.cache_data(ttl=60) # Cache seller products for 1 minute
        def get_seller_products(_seller_id):
            """Fetches products listed by a specific seller."""
            products = []
            conn = None
            try:
                conn = get_db_connection()
                if not conn: return products # Return empty if no connection
                with conn.cursor(dictionary=True) as cursor:
                    # Assuming Product table has a seller_id column
                    cursor.execute("SELECT id, name, description, price_cents, stock_quantity, created_at FROM Product WHERE seller_id = %s ORDER BY created_at DESC", (_seller_id,))
                    products = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching seller products: {err}")
            finally:
                if conn and conn.is_connected():
                    conn.close()
            return products

        @st.cache_data(ttl=60) # Cache seller transactions for 1 minute
        def get_seller_transactions(_seller_id):
            """Fetches transactions involving a specific seller."""
            transactions = []
            conn = None
            try:
                conn = get_db_connection()
                if not conn: return transactions
                with conn.cursor(dictionary=True) as cursor:
                    # This query joins Order, Transaction, and Product to get details relevant to the seller
                    query = """
                        SELECT t.id as transaction_id, o.id as order_id, o.order_date, p.name as product_name, 
                               t.quantity, t.price_at_transaction_cents, u.email as buyer_email
                        FROM Transaction t
                        JOIN `Order` o ON t.order_id = o.id
                        JOIN Product p ON t.product_id = p.id
                        JOIN User u ON o.buyer_id = u.id
                        WHERE p.seller_id = %s
                        ORDER BY o.order_date DESC
                    """
                    cursor.execute(query, (_seller_id,))
                    transactions = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching seller transactions: {err}")
            finally:
                if conn and conn.is_connected():
                    conn.close()
            return transactions

        @st.cache_data(ttl=60) # Cache seller reviews for 1 minute
        def get_seller_reviews(_seller_id):
            """Fetches reviews for products sold by a specific seller."""
            reviews = []
            conn = None
            try:
                conn = get_db_connection()
                if not conn: return reviews
                with conn.cursor(dictionary=True) as cursor:
                    query = """
                        SELECT r.id as review_id, p.name as product_name, r.rating, r.text, r.created_at, u.email as buyer_email
                        FROM Review r
                        JOIN Product p ON r.product_id = p.id
                        JOIN User u ON r.buyer_id = u.id
                        WHERE p.seller_id = %s
                        ORDER BY r.created_at DESC
                    """
                    cursor.execute(query, (_seller_id,))
                    reviews = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching seller reviews: {err}")
            finally:
                if conn and conn.is_connected():
                    conn.close()
            return reviews


        # --- Seller Dashboard Tabs ---
        tab1, tab2, tab3 = st.tabs(["Manage Products", "View Orders/Transactions", "View Reviews"])

        with tab1:
            st.header("Manage Your Products")

            # Display existing products
            st.subheader("Your Listed Products")
            seller_products = get_seller_products(st.session_state.user_id)
            if seller_products:
                st.dataframe(pd.DataFrame(seller_products), use_container_width=True)
            else:
                st.info("You have not listed any products yet.")

            st.divider()
            # Form to add a new product
            st.subheader("Add New Product")
            with st.form("add_product_form", clear_on_submit=True):
                name = st.text_input("Product Name")
                description = st.text_area("Product Description")
                price_dollars = st.number_input("Price (USD)", min_value=0.01, step=0.01, format="%.2f")
                stock_quantity = st.number_input("Stock Quantity", min_value=0, step=1)
                submitted_add_product = st.form_submit_button("Add Product")

                if submitted_add_product:
                    if not name or not description or price_dollars <= 0:
                        st.warning("Please fill in all product details correctly.")
                    else:
                        add_prod_conn = None
                        try:
                            add_prod_conn = get_db_connection()
                            if not add_prod_conn: raise Exception("DB connection failed")
                            
                            # Re-check blacklist before action
                            if check_blacklist(add_prod_conn, st.session_state.user_id):
                                st.error("Action failed: Your account is blacklisted.")
                            else:
                                price_cents = int(price_dollars * 100)
                                cursor = add_prod_conn.cursor()
                                sql = "INSERT INTO Product (seller_id, name, description, price_cents, stock_quantity) VALUES (%s, %s, %s, %s, %s)"
                                values = (st.session_state.user_id, name, description, price_cents, stock_quantity)
                                cursor.execute(sql, values)
                                product_id = cursor.lastrowid
                                add_prod_conn.commit()
                                cursor.close()
                                log_activity(add_prod_conn, st.session_state.user_id, 'add_product', f'Product ID: {product_id}, Name: {name}')
                                st.success(f"Product '{name}' added successfully!")
                                st.cache_data.clear() # Clear product cache
                                st.rerun() # Rerun to update product list
                        except mysql.connector.Error as err:
                            if add_prod_conn: add_prod_conn.rollback()
                            st.error(f"Database error adding product: {err}")
                        except Exception as e:
                            st.error(f"Error adding product: {e}")
                        finally:
                            if add_prod_conn and add_prod_conn.is_connected():
                                add_prod_conn.close()
        with tab2:
            st.header("Your Orders and Transactions")
            seller_transactions = get_seller_transactions(st.session_state.user_id)
            if seller_transactions:
                # Convert price to dollars for display
                df_transactions = pd.DataFrame(seller_transactions)
                df_transactions['price_at_transaction_dollars'] = df_transactions['price_at_transaction_cents'] / 100
                st.dataframe(df_transactions[['transaction_id', 'order_id', 'order_date', 'product_name', 'quantity', 'price_at_transaction_dollars', 'buyer_email']], use_container_width=True)
            else:
                st.info("No transactions found for your products yet.")

        with tab3:
            st.header("Reviews for Your Products")
            seller_reviews_data = get_seller_reviews(st.session_state.user_id)
            if seller_reviews_data:
                st.dataframe(pd.DataFrame(seller_reviews_data), use_container_width=True)
            else:
                st.info("No reviews found for your products yet.")


    elif st.session_state.role == 'buyer':
        # --- Buyer Dashboard ---
        st.title("Welcome, Buyer!")
        conn = get_db_connection() # General connection for this dashboard section
        if not conn:
            st.error("Database connection failed. Cannot load Buyer Dashboard.")
            st.stop() # Stop execution if no DB connection

        is_blacklisted_buyer = False
        try:
            is_blacklisted_buyer = check_blacklist(conn, st.session_state.user_id)
        except mysql.connector.Error as err:
            st.error(f"Error checking buyer blacklist status: {err}")
            st.stop()
        # No finally block to close conn here, as it's used by helper functions within tabs.
        # It will be closed at the end of the buyer dashboard section.

        if is_blacklisted_buyer:
            st.error("Your buyer account is currently blacklisted. Access denied.")
            log_activity(conn, st.session_state.user_id, 'buyer_blacklist_block', 'Buyer attempted access while blacklisted')
            if conn and conn.is_connected(): conn.close() # Close connection before stopping
            st.stop()

        # --- Helper Functions (Scoped to Buyer) ---
        def get_user_email(conn_db, user_id_to_fetch):
            """Fetches a user's email by their ID."""
            email = "N/A"
            cursor = None
            try:
                cursor = conn_db.cursor(dictionary=True)
                cursor.execute("SELECT email FROM User WHERE id = %s", (user_id_to_fetch,))
                result = cursor.fetchone()
                if result:
                    email = result['email']
            except mysql.connector.Error as err:
                st.warning(f"Could not fetch email for user {user_id_to_fetch}: {err}")
            finally:
                if cursor:
                    cursor.close()
            return email

        # --- Wallet Functions (copied from Admin for now, consider moving to utils if truly shared) ---
        @st.cache_data(ttl=30) # Cache balance for 30 seconds
        def get_wallet_balance(_conn, user_id):
            """Queries Wallet table, returns balance_cents."""
            balance = 0
            cursor = None
            try:
                with _conn.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT balance_cents FROM Wallet WHERE user_id = %s", (user_id,))
                    result = cursor.fetchone()
                    if result:
                        balance = result['balance_cents']
            except mysql.connector.Error as err:
                st.error(f"Error fetching wallet balance: {err}")
            return balance

        def update_wallet_balance(_conn, user_id, amount_change_cents):
            """Updates Wallet set balance_cents = balance_cents + amount_change_cents."""
            cursor = None
            try:
                with _conn.cursor() as cursor: # Use 'with' for cursor management
                    cursor.execute(
                        "UPDATE Wallet SET balance_cents = balance_cents + %s WHERE user_id = %s",
                        (amount_change_cents, user_id)
                    )
                    if cursor.rowcount == 0: # Wallet might not exist
                        cursor.execute("INSERT INTO Wallet (user_id, balance_cents) VALUES (%s, %s)", (user_id, amount_change_cents))
                # No commit here, handled by caller
                return True
            except mysql.connector.Error as err:
                st.error(f"Error updating wallet balance: {err}")
                return False


        # Check and display wallet balance (moved outside tabs for general visibility)
        wallet_conn_buyer = None
        try:
            wallet_conn_buyer = get_db_connection()
            if wallet_conn_buyer:
                balance_cents = get_wallet_balance(wallet_conn_buyer, st.session_state.user_id)
                st.sidebar.metric("Your Wallet Balance", f"${balance_cents / 100:.2f}")
            else:
                st.sidebar.warning("Could not fetch wallet balance.")
        except Exception as e_wallet:
            st.sidebar.error(f"Error fetching wallet: {e_wallet}")
        finally:
            if wallet_conn_buyer and wallet_conn_buyer.is_connected():
                wallet_conn_buyer.close()


        # --- Buyer Dashboard Tabs ---
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["Products", "Cart", "My Orders", "Submit Review", "Customer Support"])

        # --- Products Tab ---
        @st.cache_data(ttl=60) # Cache for 1 minute
        def get_products(_conn):
            """Fetches available products from the database."""
            products = []
            cursor = None # Define cursor outside try for broader scope in finally
            try:
                # Ensure connection is active before creating cursor
                if not _conn or not _conn.is_connected():
                    # Attempt to reconnect or get a new connection if necessary
                    # For simplicity, we'll assume _conn is valid or this function is called with a valid one.
                    # If not, an error will be raised by cursor creation.
                    st.warning("Product fetch: DB connection lost or invalid.")
                    return products # Return empty list

                with _conn.cursor(dictionary=True) as cursor:
                    # Fetch products that have stock
                    cursor.execute("SELECT id, name, description, price_cents, stock_quantity, seller_id FROM Product WHERE stock_quantity > 0 ORDER BY created_at DESC")
                    products_raw = cursor.fetchall()
                    # Get seller emails (can be slow if many products, consider optimizing)
                    # This part is removed to avoid N+1 query issues within a cached function.
                    # Seller info can be fetched on demand or joined differently if needed.
                    products = products_raw # Directly use raw products
            except mysql.connector.Error as err:
                st.error(f"Error fetching products: {err}")
            # Removed finally block for cursor close as 'with' statement handles it
            # Removed finally block for _conn.close() as _conn is passed in and managed by caller
            return products

        # --- Order History Function ---
        @st.cache_data(ttl=60)
        def get_buyer_orders(_conn, user_id):
            """Fetches orders from Order table for the user."""
            orders = []
            cursor = None
            try:
                with _conn.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT id, order_date, total_amount_cents, status FROM `Order` WHERE buyer_id = %s ORDER BY order_date DESC", (user_id,))
                    orders = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching orders: {err}")
            return orders

        # --- Function to get products for review ---
        @st.cache_data(ttl=60)
        def get_order_products_for_review(_conn, user_id):
            """Fetches products from transactions linked to the user's completed orders
               that have not yet been reviewed by this user."""
            items = []
            cursor = None
            try:
                with _conn.cursor(dictionary=True) as cursor:
                    # Select products from transactions where the order is 'completed'
                    # and for which no review exists from this buyer for this product.
                    # This assumes a simple "no review yet" check.
                    # A more complex system might track review per transaction_item_id if multiple of same product in different orders.
                    query = """
                        SELECT DISTINCT t.product_id, p.name as product_name, t.id as transaction_id
                        FROM Transaction t
                        JOIN Product p ON t.product_id = p.id
                        JOIN `Order` o ON t.order_id = o.id
                        WHERE o.buyer_id = %s AND o.status = 'completed' 
                        AND NOT EXISTS (
                            SELECT 1 FROM Review r 
                            WHERE r.buyer_id = o.buyer_id AND r.product_id = t.product_id
                        )
                        ORDER BY p.name;
                    """
                    # The subquery for NOT EXISTS checks if a review from this buyer for this product already exists.
                    # This means a product can only be reviewed once by a buyer, regardless of how many times it was ordered.
                    # If review per transaction is needed, the schema and query would be different.
                    cursor.execute(query, (user_id,))
                    items = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching products for review: {err}")
            return items

        def get_product_details(_conn, product_id):
             """Fetches details for a single product."""
             product = None
             try:
                 with _conn.cursor(dictionary=True) as cursor:
                     cursor.execute("SELECT name, description, price_cents FROM Product WHERE id = %s", (product_id,))
                     product = cursor.fetchone()
             except mysql.connector.Error as err:
                 st.error(f"Error fetching product details: {err}")
             return product

        def handle_checkout():
            checkout_conn = None # Use a separate connection variable for clarity
            try:
                checkout_conn = get_db_connection()
                if not checkout_conn:
                    st.error("Checkout failed: Could not connect to the database.")
                    return

                # Re-check blacklist before proceeding with checkout
                if check_blacklist(checkout_conn, st.session_state.user_id):
                    st.error("Checkout failed: Your account is blacklisted.")
                    return

                cart_items = st.session_state.get('cart', {})
                if not cart_items:
                    st.warning("Your cart is empty.")
                    return

                total_amount_cents = 0
                product_details_for_order = []

                cursor = checkout_conn.cursor(dictionary=True) # Use one cursor for multiple reads

                # 1. Validate cart items and calculate total
                for product_id, quantity in cart_items.items():
                    cursor.execute("SELECT name, price_cents, stock_quantity FROM Product WHERE id = %s", (product_id,))
                    product = cursor.fetchone()
                    if not product:
                        st.error(f"Product ID {product_id} not found. Please remove from cart.")
                        return
                    if product['stock_quantity'] < quantity:
                        st.error(f"Not enough stock for {product['name']}. Available: {product['stock_quantity']}.")
                        return
                    total_amount_cents += product['price_cents'] * quantity
                    product_details_for_order.append({
                        'id': product_id,
                        'price_at_transaction_cents': product['price_cents'],
                        'quantity': quantity,
                        'name': product['name'] # For logging/display
                    })
                
                # 2. Check wallet balance
                cursor.execute("SELECT balance_cents FROM Wallet WHERE user_id = %s", (st.session_state.user_id,))
                wallet = cursor.fetchone()
                if not wallet or wallet['balance_cents'] < total_amount_cents:
                    st.error("Insufficient wallet balance for this order.")
                    # Optionally, guide user to add funds if that feature exists
                    return

                # --- Start Transaction ---
                checkout_conn.start_transaction()
                
                try:
                    # 3. Create Order
                    order_sql = "INSERT INTO `Order` (buyer_id, order_date, total_amount_cents, status) VALUES (%s, %s, %s, %s)"
                    order_values = (st.session_state.user_id, datetime.now(), total_amount_cents, 'completed') # Assuming 'completed' for simplicity
                    cursor.execute(order_sql, order_values)
                    order_id = cursor.lastrowid

                    # 4. Create Transactions and Update Stock
                    for item in product_details_for_order:
                        trans_sql = "INSERT INTO Transaction (order_id, product_id, quantity, price_at_transaction_cents) VALUES (%s, %s, %s, %s)"
                        trans_values = (order_id, item['id'], item['quantity'], item['price_at_transaction_cents'])
                        cursor.execute(trans_sql, trans_values)

                        # Update stock
                        stock_sql = "UPDATE Product SET stock_quantity = stock_quantity - %s WHERE id = %s"
                        cursor.execute(stock_sql, (item['quantity'], item['id']))
                    
                    # 5. Update Wallet Balance
                    wallet_update_sql = "UPDATE Wallet SET balance_cents = balance_cents - %s WHERE user_id = %s"
                    cursor.execute(wallet_update_sql, (total_amount_cents, st.session_state.user_id))

                    checkout_conn.commit()
                    # --- Transaction End ---
                    
                    # Log successful checkout activity
                    log_activity(checkout_conn, st.session_state.user_id, 'checkout_success', f"Order ID: {order_id}, Total: {total_amount_cents/100:.2f}")

                    st.success(f"Checkout successful! Your order ID is {order_id}.")
                    st.session_state.cart = {} # Clear cart
                    # ANOMALY AND BLACKLIST CHECKS START
                    db_conn_anomaly_check = None
                    try:
                        db_conn_anomaly_check = get_db_connection()
                        if db_conn_anomaly_check and st.session_state.get('user_id') and st.session_state.get('role'):
                            current_user_id = st.session_state.user_id # Capture before potential deletion
                            current_user_role = st.session_state.role # Capture before potential deletion
                            run_all_user_anomaly_checks_and_log(db_conn_anomaly_check, current_user_id, current_user_role)
                            blacklist_result = check_and_blacklist_user_if_needed(db_conn_anomaly_check, current_user_id)
                            if blacklist_result.get('blacklisted'):
                                st.error("YOU ARE BLACKLISTED FOR ATTEMPTING TO FRAUD!")
                                # Clear session state for logout, preserving blacklist message flag
                                keys_to_del_on_blacklist_action = [k for k in st.session_state.keys() if k not in ['show_blacklisted_message_duration']]
                                for k_del in keys_to_del_on_blacklist_action:
                                    del st.session_state[k_del]
                                st.session_state.logged_in = False
                                st.session_state.user_id = None # Explicitly clear
                                st.session_state.role = None # Explicitly clear
                                st.session_state.show_blacklisted_message_duration = 5
                                st.rerun()
                    except mysql.connector.Error as e_anomaly:
                        st.warning(f"Database error during post-action anomaly/blacklist check: {e_anomaly}")
                    except Exception as e_generic_anomaly:
                        st.warning(f"Unexpected error during post-action anomaly/blacklist check: {e_generic_anomaly}")
                    finally:
                        if db_conn_anomaly_check and db_conn_anomaly_check.is_connected():
                            db_conn_anomaly_check.close()
                    # ANOMALY AND BLACKLIST CHECKS END
                    st.cache_data.clear() # Clear relevant caches (products, orders, wallet)
                    st.rerun() # Rerun to reflect changes

                except mysql.connector.Error as err_transact:
                    if checkout_conn: checkout_conn.rollback()
                    st.error(f"Checkout failed during transaction: {err_transact}")
                    log_activity(checkout_conn, st.session_state.user_id, 'checkout_failure_db', str(err_transact))

                finally: # This finally is for the inner try (transaction block)
                    if cursor: cursor.close() # Close cursor used for checkout steps
            
            except mysql.connector.Error as err_main: # Error in initial connection or pre-transaction checks
                st.error(f"Checkout failed: {err_main}")
                log_activity(None, st.session_state.user_id, 'checkout_failure_setup', str(err_main)) # conn might be None
            except Exception as e_main: # Other unexpected errors
                st.error(f"An unexpected error occurred during checkout: {e_main}")
                log_activity(None, st.session_state.user_id, 'checkout_failure_unexpected', str(e_main))
            finally: # This finally is for the outer try (handle_checkout function)
                if checkout_conn and checkout_conn.is_connected():
                    checkout_conn.close()


        with tab1: # Products Tab
            st.header("Available Products")
            # Use the main connection 'conn' established for the buyer dashboard
            products = get_products(conn)
            if products:
                # Create columns for product display
                cols = st.columns(3) # Adjust number of columns as needed
                for idx, product in enumerate(products):
                    with cols[idx % len(cols)]:
                        with st.container(border=True):
                            st.subheader(product['name'])
                            st.caption(f"Seller ID: {product['seller_id']}") # Display seller ID
                            st.write(product['description'])
                            st.write(f"Price: ${product['price_cents'] / 100:.2f}")
                            st.write(f"Stock: {product['stock_quantity']}")

                            quantity_to_add = st.number_input(f"Quantity##{product['id']}", min_value=1, max_value=product['stock_quantity'], value=1, step=1, key=f"qty_{product['id']}")
                            if st.button("Add to Cart", key=f"add_{product['id']}"):
                                add_conn = None # Connection for this specific action
                                try:
                                    add_conn = get_db_connection()
                                    if not add_conn: raise Exception("DB connection failed for add to cart")

                                    # Re-check blacklist before action
                                    if check_blacklist(add_conn, st.session_state.user_id):
                                        st.error("Action failed: Your account is blacklisted.")
                                    else:
                                        cart = st.session_state.get('cart', {})
                                        cart[product['id']] = cart.get(product['id'], 0) + quantity_to_add
                                        st.session_state.cart = cart
                                        # Log activity for adding to cart
                                        log_activity(add_conn, st.session_state.user_id, 'add_to_cart', f"Product ID: {product['id']}, Quantity: {quantity_to_add}")
                                        st.cache_data.clear() # Clear product cache if needed, or specific cart cache
                                        st.rerun() # Rerun to reflect cart changes
                                        st.success(f"Added {quantity_to_add} of {product['name']} to cart.")
                                        # ANOMALY AND BLACKLIST CHECKS START
                                        db_conn_anomaly_check = None
                                        try:
                                            db_conn_anomaly_check = get_db_connection()
                                            if db_conn_anomaly_check and st.session_state.get('user_id') and st.session_state.get('role'):
                                                current_user_id = st.session_state.user_id # Capture before potential deletion
                                                current_user_role = st.session_state.role # Capture before potential deletion
                                                run_all_user_anomaly_checks_and_log(db_conn_anomaly_check, current_user_id, current_user_role)
                                                blacklist_result = check_and_blacklist_user_if_needed(db_conn_anomaly_check, current_user_id)
                                                if blacklist_result.get('blacklisted'):
                                                    st.error("YOU ARE BLACKLISTED FOR ATTEMPTING TO FRAUD!")
                                                    # Clear session state for logout, preserving blacklist message flag
                                                    keys_to_del_on_blacklist_action = [k for k in st.session_state.keys() if k not in ['show_blacklisted_message_duration']]
                                                    for k_del in keys_to_del_on_blacklist_action:
                                                        del st.session_state[k_del]
                                                    st.session_state.logged_in = False
                                                    st.session_state.user_id = None # Explicitly clear
                                                    st.session_state.role = None # Explicitly clear
                                                    st.session_state.show_blacklisted_message_duration = 5
                                                    st.rerun()
                                        except mysql.connector.Error as e_anomaly:
                                            st.warning(f"Database error during post-action anomaly/blacklist check: {e_anomaly}")
                                        except Exception as e_generic_anomaly:
                                            st.warning(f"Unexpected error during post-action anomaly/blacklist check: {e_generic_anomaly}")
                                        finally:
                                            if db_conn_anomaly_check and db_conn_anomaly_check.is_connected():
                                                db_conn_anomaly_check.close()
                                        # ANOMALY AND BLACKLIST CHECKS END

                                except mysql.connector.Error as err_add_cart_db:
                                    st.error(f"DB error adding to cart: {err_add_cart_db}")
                                except Exception as err_add_cart:
                                    st.error(f"Error adding to cart: {err_add_cart}")
                                finally:
                                    if add_conn and add_conn.is_connected():
                                        add_conn.close()
            else:
                st.info("No products available at the moment.")

        with tab2: # Cart Tab
            st.header("Your Shopping Cart")
            cart_items = st.session_state.get('cart', {})
            if not cart_items:
                st.info("Your cart is empty.")
            else:
                cart_items_details = []
                total_cart_value = 0
                cart_conn = None
                try:
                    cart_conn = get_db_connection()
                    if not cart_conn: raise Exception("DB connection failed for cart display")
                    
                    for product_id, quantity in cart_items.items():
                        product_info = get_product_details(cart_conn, product_id) # Use existing connection
                        if product_info:
                            item_total = product_info['price_cents'] * quantity
                            cart_items_details.append({
                                "Product ID": product_id,
                                "Name": product_info['name'],
                                "Quantity": quantity,
                                "Price per item": f"${product_info['price_cents'] / 100:.2f}",
                                "Total": f"${item_total / 100:.2f}"
                            })
                            total_cart_value += item_total
                        else:
                            # Product might have been removed or stock depleted
                            st.warning(f"Product ID {product_id} details not found. It might be unavailable.")
                            # Optionally, remove from cart here:
                            # del st.session_state.cart[product_id]
                            # st.rerun()

                    if cart_items_details:
                        st.dataframe(pd.DataFrame(cart_items_details), use_container_width=True)
                        st.subheader(f"Total Cart Value: ${total_cart_value / 100:.2f}")

                        if st.button("Proceed to Checkout", key="checkout_button"):
                            handle_checkout() # Call the checkout handler

                        if st.button("Clear Cart", key="clear_cart_button"):
                            st.session_state.cart = {}
                            st.rerun()
                    else:
                        st.info("Your cart is empty or items became unavailable.") # If all items failed to load

                except Exception as e_cart_display:
                    st.error(f"Error displaying cart: {e_cart_display}")
                finally:
                    if cart_conn and cart_conn.is_connected():
                        cart_conn.close()

        with tab3: # My Orders Tab
            st.header("My Orders")
            orders_conn = None
            try:
                orders_conn = get_db_connection()
                if not orders_conn: raise Exception("DB connection failed for orders display")
                
                buyer_orders_data = get_buyer_orders(orders_conn, st.session_state.user_id)
                if buyer_orders_data:
                    df_orders = pd.DataFrame(buyer_orders_data)
                    df_orders['total_amount_dollars'] = df_orders['total_amount_cents'] / 100
                    st.dataframe(df_orders[['id', 'order_date', 'total_amount_dollars', 'status']], use_container_width=True)
                else:
                    st.info("You have no orders yet.")
            except Exception as e_orders_display:
                st.error(f"Error displaying orders: {e_orders_display}")
            finally:
                if orders_conn and orders_conn.is_connected():
                    orders_conn.close()


        with tab4: # Submit Review Tab
            st.header("Submit Review")
            review_conn = None # Connection for this tab's initial data load
            try:
                review_conn = get_db_connection()
                if not review_conn: raise Exception("DB connection failed for review section")

                items_to_review = get_order_products_for_review(review_conn, st.session_state.user_id)

                if not items_to_review:
                    st.info("No items to review at the moment. You can review products after your order is completed.")
                else:
                    # Create a mapping from display string to item details for the selectbox
                    options = {f"{item['product_name']} (Product ID: {item['product_id']}, Transaction: {item['transaction_id']})": item for item in items_to_review}
                    selected_option = st.selectbox("Select Item to Review", options.keys())

                    if selected_option:
                        selected_item = options[selected_option]
                        product_id_to_review = selected_item['product_id']
                        # order_id_to_review = selected_item['order_id'] # Cannot reliably get order_id

                        with st.form("review_form", clear_on_submit=True):
                            rating = st.slider("Rating (1=Poor, 5=Excellent)", 1, 5, 3)
                            review_text = st.text_area("Your Review")
                            submitted = st.form_submit_button("Submit Review")

                            if submitted:
                                review_submit_conn = None
                                try:
                                    review_submit_conn = get_db_connection()
                                    if not review_submit_conn: raise Exception("DB connection failed")

                                    # Re-check blacklist
                                    if check_blacklist(review_submit_conn, st.session_state.user_id):
                                         st.error("Action failed: Your account is blacklisted.")
                                    elif not review_text:
                                         st.warning("Please provide some text for your review.")
                                    else:
                                        cursor = review_submit_conn.cursor()
                                        # Modified INSERT to match Review schema (removed order_id, seller_id; changed review_date to created_at)
                                        insert_sql = """
                                            INSERT INTO Review (buyer_id, product_id, rating, text, created_at)
                                            VALUES (%s, %s, %s, %s, %s)
                                        """
                                        # Removed order_id_to_review and seller_id subquery
                                        values = (st.session_state.user_id, product_id_to_review, rating, review_text, datetime.now())
                                        cursor.execute(insert_sql, values)
                                        review_id = cursor.lastrowid
                                        review_submit_conn.commit()
                                        print(f"DEBUG: Review submitted with ID: {review_id}") # DEBUG PRINT
                                        cursor.close()

                                        # Log activity
                                        log_activity(review_submit_conn, st.session_state.user_id, 'submit_review', f'Review ID: {review_id}')
                                        # ANOMALY AND BLACKLIST CHECKS START
                                        db_conn_anomaly_check = None
                                        try:
                                            db_conn_anomaly_check = get_db_connection()
                                            if db_conn_anomaly_check and st.session_state.get('user_id') and st.session_state.get('role'):
                                                current_user_id = st.session_state.user_id # Capture before potential deletion
                                                current_user_role = st.session_state.role # Capture before potential deletion
                                                run_all_user_anomaly_checks_and_log(db_conn_anomaly_check, current_user_id, current_user_role)
                                                blacklist_result = check_and_blacklist_user_if_needed(db_conn_anomaly_check, current_user_id)
                                                if blacklist_result.get('blacklisted'):
                                                    st.error("YOU ARE BLACKLISTED FOR ATTEMPTING TO FRAUD!")
                                                    # Clear session state for logout, preserving blacklist message flag
                                                    keys_to_del_on_blacklist_action = [k for k in st.session_state.keys() if k not in ['show_blacklisted_message_duration']]
                                                    for k_del in keys_to_del_on_blacklist_action:
                                                        del st.session_state[k_del]
                                                    st.session_state.logged_in = False
                                                    st.session_state.user_id = None # Explicitly clear
                                                    st.session_state.role = None # Explicitly clear
                                                    st.session_state.show_blacklisted_message_duration = 5
                                                    st.rerun()
                                        except mysql.connector.Error as e_anomaly:
                                            st.warning(f"Database error during post-action anomaly/blacklist check: {e_anomaly}")
                                        except Exception as e_generic_anomaly:
                                            st.warning(f"Unexpected error during post-action anomaly/blacklist check: {e_generic_anomaly}")
                                        finally:
                                            if db_conn_anomaly_check and db_conn_anomaly_check.is_connected():
                                                db_conn_anomaly_check.close()
                                        # ANOMALY AND BLACKLIST CHECKS END

                                        # Clear cache to update review lists
                                        st.cache_data.clear()
                                        st.success("Review submitted successfully!")
                                        # Consider adding st.rerun() if needed, but clearing cache might be enough

                                        # Run fraud checks
                                        run_fraud_checks(review_submit_conn, 'new_review', {
                                            'review_id': review_id,
                                            'buyer_id': st.session_state.user_id,
                                            'product_id': product_id_to_review,
                                            'rating': rating
                                        })

                                        st.success("Review submitted successfully!")
                                        st.cache_data.clear() # Clear cache to refresh reviewable items list
                                        st.rerun() # Rerun to update the selectbox

                                except mysql.connector.Error as err:
                                    if review_submit_conn: review_submit_conn.rollback()
                                    st.error(f"Database error submitting review: {err}")
                                except Exception as e:
                                     st.error(f"Error submitting review: {e}")
                                finally:
                                    if review_submit_conn and review_submit_conn.is_connected():
                                        review_submit_conn.close()

            except Exception as e:
                 st.error(f"Error loading review section: {e}")
            finally:
                # Close the initial connection for this tab if it's still open
                 if review_conn and review_conn.is_connected():
                     review_conn.close()


        with tab5: # Customer Support Tab
            st.header("Customer Support")
            support_conn = None
            try:
                support_conn = get_db_connection()
                if not support_conn: raise Exception("DB connection failed")

                buyer_orders_list = get_buyer_orders(support_conn, st.session_state.user_id)
                order_options = {f"Order ID: {order['id']} ({order['order_date']})": order['id'] for order in buyer_orders_list}
                order_options["None (General Inquiry)"] = None # Add option for no specific order

                with st.form("support_form", clear_on_submit=True):
                    selected_order_display = st.selectbox(
                        "Related Order (Optional)",
                         options=order_options.keys()
                    )
                    selected_order_id = order_options[selected_order_display]

                    issue_type = st.selectbox(
                        "Issue Type",
                        ["Item not received", "Wrong item", "Damaged item", "Payment issue", "Review dispute", "Account issue", "Other"]
                    )
                    description = st.text_area("Please describe the issue in detail:")
                    submitted = st.form_submit_button("Submit Support Ticket")

                    if submitted:
                        support_submit_conn = None
                        try:
                            support_submit_conn = get_db_connection()
                            if not support_submit_conn: raise Exception("DB connection failed")

                            # Re-check blacklist
                            if check_blacklist(support_submit_conn, st.session_state.user_id):
                                st.error("Action failed: Your account is blacklisted.")
                            elif not description:
                                st.warning("Please provide a description of your issue.")
                            else:
                                cursor = support_submit_conn.cursor()
                                insert_sql = """
                                    INSERT INTO CustomerSupport (buyer_id, order_id, issue_type, description, status, created_at)
                                    VALUES (%s, %s, %s, %s, %s, %s)
                                """
                                values = (st.session_state.user_id, selected_order_id, issue_type, description, 'open', datetime.now())
                                cursor.execute(insert_sql, values)
                                ticket_id = cursor.lastrowid
                                support_submit_conn.commit()
                                cursor.close()

                                # Log activity
                                log_activity(support_submit_conn, st.session_state.user_id, 'submit_support_ticket', f'Ticket ID: {ticket_id}')
                                # ANOMALY AND BLACKLIST CHECKS START
                                db_conn_anomaly_check = None
                                try:
                                    db_conn_anomaly_check = get_db_connection()
                                    if db_conn_anomaly_check and st.session_state.get('user_id') and st.session_state.get('role'):
                                        current_user_id = st.session_state.user_id # Capture before potential deletion
                                        current_user_role = st.session_state.role # Capture before potential deletion
                                        run_all_user_anomaly_checks_and_log(db_conn_anomaly_check, current_user_id, current_user_role)
                                        blacklist_result = check_and_blacklist_user_if_needed(db_conn_anomaly_check, current_user_id)
                                        if blacklist_result.get('blacklisted'):
                                            st.error("YOU ARE BLACKLISTED FOR ATTEMPTING TO FRAUD!")
                                            # Clear session state for logout, preserving blacklist message flag
                                            keys_to_del_on_blacklist_action = [k for k in st.session_state.keys() if k not in ['show_blacklisted_message_duration']]
                                            for k_del in keys_to_del_on_blacklist_action:
                                                del st.session_state[k_del]
                                            st.session_state.logged_in = False
                                            st.session_state.user_id = None # Explicitly clear
                                            st.session_state.role = None # Explicitly clear
                                            st.session_state.show_blacklisted_message_duration = 5
                                            st.rerun()
                                except mysql.connector.Error as e_anomaly:
                                    st.warning(f"Database error during post-action anomaly/blacklist check: {e_anomaly}")
                                except Exception as e_generic_anomaly:
                                    st.warning(f"Unexpected error during post-action anomaly/blacklist check: {e_generic_anomaly}")
                                finally:
                                    if db_conn_anomaly_check and db_conn_anomaly_check.is_connected():
                                        db_conn_anomaly_check.close()
                                # ANOMALY AND BLACKLIST CHECKS END

                                # Run fraud checks
                                run_fraud_checks(support_submit_conn, 'new_support_ticket', {
                                    'ticket_id': ticket_id,
                                    'buyer_id': st.session_state.user_id,
                                    'order_id': selected_order_id,
                                    'issue_type': issue_type
                                })

                                st.success(f"Support ticket #{ticket_id} submitted successfully. We will get back to you soon.")

                        except mysql.connector.Error as err:
                            if support_submit_conn: support_submit_conn.rollback()
                            st.error(f"Database error submitting ticket: {err}")
                        except Exception as e:
                            st.error(f"Error submitting ticket: {e}")
                        finally:
                            if support_submit_conn and support_submit_conn.is_connected():
                                support_submit_conn.close()

            except Exception as e:
                 st.error(f"Error loading support section: {e}")
            finally:
                 # Close the initial connection for this tab if it's still open
                 if support_conn and support_conn.is_connected():
                     support_conn.close()
        
        # Close the main connection for the buyer dashboard if it's still open
        if conn and conn.is_connected():
            conn.close()

    else: # Should not happen if logged_in is True and role is set
        st.error("Invalid user role detected. Please logout and login again.")
        if conn and conn.is_connected(): # Close general connection if open
            conn.close()