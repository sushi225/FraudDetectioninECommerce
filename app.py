import streamlit as st
import mysql.connector
import os
from dotenv import load_dotenv
import bcrypt
import pandas as pd
from datetime import datetime, date # Added date for blacklist duration
from utils import log_activity, check_blacklist, get_db_connection, get_all_reviews, get_all_customer_tickets # Moved get_db_connection here for consistency
from fraud_detection import run_fraud_checks # Import fraud detection function

# Load environment variables from .env file
load_dotenv()

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
                # Ensure both are bytes for bcrypt
                if isinstance(stored_hash, str):
                    stored_hash = stored_hash.encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
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
&lt;style&gt;
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
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] &gt; div,
    .stDateInput input, .stNumberInput input,
    .stMetric, .stMetric label, .stMetric div[data-testid="stMetricValue"],
    .stDataFrame {{
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: black !important;
    }}

    /* Buttons */
    .stButton &gt; button {{
        background-color: red !important;
        color: white !important; /* Text on red buttons */
        border: 1px solid red !important;
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
    }}
    .stButton &gt; button:hover {{
        background-color: darkred !important;
        border-color: darkred !important;
        color: white !important;
    }}
    .stButton &gt; button:active {{
        background-color: #b20000 !important; /* Even darker red for active state */
        border-color: #b20000 !important;
        color: white !important;
    }}
    .stButton &gt; button:focus {{
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
    .stTabs [data-baseweb="tab"][aria-selected="true"] &gt; div {{
         color: white !important; /* Ensure text within the active tab div is white */
    }}

    /* Markdown specific styling */
    .stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6, .stMarkdown strong, .stMarkdown em, .stMarkdown code, .stMarkdown pre {{
        font-family: "SF Pro Bold", "Helvetica Neue", Helvetica, Arial, sans-serif !important;
        color: black !important;
    }}

    /* Input fields styling */
    .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] &gt; div, .stDateInput input, .stNumberInput input {{
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

&lt;/style&gt;
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
                if user_id:
                    st.session_state.logged_in = True
                    st.session_state.user_id = user_id
                    st.session_state.role = role
                    conn = get_db_connection()
                    if conn:
                        log_activity(conn, user_id, 'login') # Log successful login
                        if conn.is_connected():
                             conn.close()
                    st.rerun()
                else:
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

        @st.cache_data(ttl=60)
        def get_recent_anomalies(_conn, limit=10):
            """Fetches the latest anomaly logs."""
            anomalies = []
            cursor = None
            try:
                cursor = _conn.cursor(dictionary=True)
                query = "SELECT * FROM AnomalyDetectionLog ORDER BY timestamp DESC LIMIT %s"
                cursor.execute(query, (limit,))
                anomalies = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching recent anomalies: {err}")
            finally:
                if cursor:
                    cursor.close()
            return anomalies

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
                    FROM LoggingActivity l
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

        @st.cache_data(ttl=30)
        def get_all_anomalies(_conn, limit=100):
             """Fetches all anomaly logs."""
             anomalies = []
             cursor = None
             try:
                 cursor = _conn.cursor(dictionary=True)
                 query = "SELECT * FROM AnomalyDetectionLog ORDER BY timestamp DESC LIMIT %s"
                 cursor.execute(query, (limit,))
                 anomalies = cursor.fetchall()
             except mysql.connector.Error as err:
                 st.error(f"Error fetching all anomalies: {err}")
             finally:
                 if cursor:
                     cursor.close()
             return anomalies

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
        tab_overview, tab_users, tab_create_user, tab_wallet, tab_activity, tab_anomaly, tab_all_reviews, tab_all_tickets = st.tabs([
            "Overview", "User Management", "Create User", "Wallet Management", "Activity Log", "Anomaly Log", "All Reviews", "All Customer Tickets"
        ])

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
            recent_anomalies = get_recent_anomalies(conn_tabs)
            if recent_anomalies:
                st.dataframe(pd.DataFrame(recent_anomalies), use_container_width=True)
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
                st.metric("Total Orders", get_count(conn_tabs, "`Order`"))
            with col4:
                st.metric("Open Support Tickets", get_count(conn_tabs, "CustomerSupport", "status='open'")) # Example with condition

        # --- User Management Tab ---
        with tab_users:
            st.header("User Management")
            st.dataframe(users_df, use_container_width=True)

            st.divider()
            st.subheader("Blacklist User")

            if not users_df.empty:
                col1, col2 = st.columns([1, 2])
                with col1:
                     selected_user_id_blacklist = st.selectbox(
                         "Select User ID to Blacklist",
                         options=users_df['id'],
                         key="blacklist_user_select" # Unique key
                     )
                # Form needs to be outside columns if submit button is shared, or inside if specific to a column
                with st.form("blacklist_form"):
                    reason = st.text_area("Reason for Blacklist*", help="Provide a clear reason for blacklisting.")
                    blocked_until_date = st.date_input("Block Until (Optional)", value=None, min_value=date.today())
                    submitted_blacklist = st.form_submit_button("Blacklist User")

                    if submitted_blacklist:
                        if not reason:
                            st.warning("Reason is required to blacklist a user.")
                        elif selected_user_id_blacklist == st.session_state.user_id:
                             st.error("Admin cannot blacklist themselves through this interface.")
                        else:
                            blacklist_conn = None
                            try:
                                blacklist_conn = get_db_connection()
                                if not blacklist_conn: raise Exception("DB Connection failed")

                                cursor = blacklist_conn.cursor()
                                # Use REPLACE INTO to handle cases where user might already be blacklisted (updates the reason/date)
                                # Or use INSERT IGNORE if you only want to insert if not present
                                query = """
                                    REPLACE INTO Blacklist (user_id, reason, blocked_until, created_at, admin_id)
                                    VALUES (%s, %s, %s, %s, %s)
                                """
                                # Convert date to string or pass None directly
                                blocked_until_sql = blocked_until_date if blocked_until_date else None
                                values = (selected_user_id_blacklist, reason, blocked_until_sql, datetime.now(), st.session_state.user_id)
                                cursor.execute(query, values)
                                blacklist_conn.commit()

                                log_activity(blacklist_conn, st.session_state.user_id, 'blacklist_user',
                                             f'Target User ID: {selected_user_id_blacklist}, Reason: {reason}, Until: {blocked_until_sql}')
                                blacklist_conn.commit() # Commit log

                                st.success(f"User ID {selected_user_id_blacklist} has been blacklisted/updated.")
                                st.cache_data.clear() # Clear relevant caches if needed
                                cursor.close()
                                st.rerun()

                            except mysql.connector.Error as err:
                                if blacklist_conn: blacklist_conn.rollback()
                                st.error(f"Database error during blacklisting: {err}")
                            except Exception as e:
                                st.error(f"An error occurred: {e}")
                            finally:
                                if blacklist_conn and blacklist_conn.is_connected():
                                    blacklist_conn.close()
            else:
                st.info("No users found to manage.")


# --- Create User Tab ---
        with tab_create_user:
            st.header("Create New User")

            def get_next_user_number(conn_db, role_prefix_str):
                """Determines the next sequential number for a user based on role."""
                cursor_next_num = None
                next_number_val = 1
                try:
                    cursor_next_num = conn_db.cursor()
                    query_next_num = "SELECT email FROM User WHERE email LIKE %s ORDER BY id DESC" # Check existing emails
                    cursor_next_num.execute(query_next_num, (f"{role_prefix_str}%@example.com",))
                    
                    max_num_found = 0
                    for row_email in cursor_next_num.fetchall():
                        email_addr_str = row_email[0]
                        try:
                            # Extract number: buyer123@example.com -> 123
                            num_part_str = email_addr_str.replace(role_prefix_str, "").split('@')[0]
                            if num_part_str.isdigit():
                                current_num = int(num_part_str)
                                if current_num > max_num_found:
                                    max_num_found = current_num
                        except ValueError:
                            continue # Skip if parsing fails for any reason
                    next_number_val = max_num_found + 1
                except mysql.connector.Error as err_next_num:
                    st.error(f"Error determining next user number for {role_prefix_str}: {err_next_num}")
                    # In case of error, this might lead to duplicate numbers if not handled carefully,
                    # or we could decide to stop creation. For now, it defaults to 1 or max_found + 1.
                finally:
                    if cursor_next_num:
                        cursor_next_num.close()
                return next_number_val

            with st.form("create_user_form", clear_on_submit=True):
                st.subheader("New User Details")
                new_user_role_selection = st.selectbox("Select Role", ["buyer", "seller"], key="new_user_role_select")
                new_user_password_input = st.text_input("Enter Password", type="password", key="new_user_password_input")
                
                create_user_button = st.form_submit_button("Create New User")

                if create_user_button:
                    if not new_user_password_input:
                        st.warning("Password is required to create a new user.")
                    else:
                        conn_create_user = None
                        try:
                            conn_create_user = get_db_connection()
                            if not conn_create_user:
                                st.error("Database connection failed. Cannot create user.")
                                st.stop()

                            # Determine the next email number
                            next_user_seq_num = get_next_user_number(conn_create_user, new_user_role_selection)
                            generated_email = f"{new_user_role_selection}{next_user_seq_num}@example.com"
                            
                            # Hash the password
                            password_bytes = new_user_password_input.encode('utf-8')
                            hashed_password_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
                            hashed_password_str = hashed_password_bytes.decode('utf-8') # Store as string
                            
                            cursor_insert_user = conn_create_user.cursor()
                            insert_query = "INSERT INTO User (email, password_hash, role) VALUES (%s, %s, %s)"
                            insert_values = (generated_email, hashed_password_str, new_user_role_selection)
                            
                            cursor_insert_user.execute(insert_query, insert_values)
                            newly_created_user_id = cursor_insert_user.lastrowid
                            conn_create_user.commit()
                            
                            log_activity(conn_create_user, st.session_state.user_id, 'admin_create_user', 
                                         f'Created User ID: {newly_created_user_id}, Email: {generated_email}, Role: {new_user_role_selection}')
                            conn_create_user.commit() # Commit the log

                            st.success(f"User '{generated_email}' ({new_user_role_selection.capitalize()}) created successfully with ID: {newly_created_user_id}!")
                            
                            # Clear caches that might hold user lists
                            st.cache_data.clear() 
                            cursor_insert_user.close()
                            st.rerun() # Rerun to refresh lists and clear form

                        except mysql.connector.Error as db_err:
                            if conn_create_user:
                                conn_create_user.rollback()
                            st.error(f"Database error during user creation: {db_err}")
                            if "Duplicate entry" in str(db_err) and "for key 'User.email'" in str(db_err):
                                st.warning(f"The email '{generated_email}' might already exist. Please try again or check logs.")
                        except Exception as e:
                            st.error(f"An unexpected error occurred: {e}")
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
                        "Select User ID to Manage Wallet",
                        options=users_df['id'],
                        key="wallet_user_select" # Unique key
                    )

                    # Display current balance
                    current_balance_cents = get_wallet_balance(conn_tabs, selected_user_id_wallet)
                    st.metric(f"Current Balance (User {selected_user_id_wallet})", f"₹{current_balance_cents / 100:.2f}")

                with col2_wallet:
                    st.subheader("Adjust Wallet Balance")
                    with st.form("wallet_adjust_form"):
                        adjustment_amount_inr = st.number_input(
                            "Amount to Add/Subtract (INR)",
                            format="%.2f",
                            step=10.0,
                            help="Positive value adds funds, negative value subtracts funds."
                        )
                        adjustment_reason = st.text_input("Reason for Adjustment*")
                        submitted_wallet_adjust = st.form_submit_button("Adjust Balance")

                        if submitted_wallet_adjust:
                            if not adjustment_reason:
                                st.warning("Reason is required for wallet adjustment.")
                            elif adjustment_amount_inr == 0:
                                st.warning("Adjustment amount cannot be zero.")
                            else:
                                wallet_conn = None
                                try:
                                    wallet_conn = get_db_connection()
                                    if not wallet_conn: raise Exception("DB Connection failed")

                                    adjustment_amount_cents = int(adjustment_amount_inr * 100)

                                    # Check current balance if subtracting to prevent negative balance (optional rule)
                                    # current_bal = get_wallet_balance(wallet_conn, selected_user_id_wallet)
                                    # if adjustment_amount_cents < 0 and current_bal + adjustment_amount_cents < 0:
                                    #     st.error("Adjustment failed: Insufficient funds.")
                                    # else:

                                    success = update_wallet_balance(wallet_conn, selected_user_id_wallet, adjustment_amount_cents)

                                    if success:
                                        log_activity(wallet_conn, st.session_state.user_id, 'adjust_wallet',
                                                     f'Target User ID: {selected_user_id_wallet}, Amount Cents: {adjustment_amount_cents}, Reason: {adjustment_reason}')
                                        wallet_conn.commit() # Commit wallet update and log
                                        st.success(f"Wallet for User ID {selected_user_id_wallet} adjusted by ₹{adjustment_amount_inr:.2f}.")
                                        st.cache_data.clear() # Clear cache to reflect changes
                                        st.rerun() # Rerun to update UI
                                        wallet_conn.commit() # Commit update and log
                                        st.success(f"Wallet balance for User ID {selected_user_id_wallet} adjusted successfully.")
                                        st.cache_data.clear() # Clear balance cache
                                        st.rerun()
                                    else:
                                        # Error already shown by update_wallet_balance
                                        wallet_conn.rollback()

                                except mysql.connector.Error as err:
                                    if wallet_conn: wallet_conn.rollback()
                                    st.error(f"Database error during wallet adjustment: {err}")
                                except Exception as e:
                                     st.error(f"An error occurred: {e}")
                                finally:
                                    if wallet_conn and wallet_conn.is_connected():
                                        wallet_conn.close()
            else:
                 st.info("No users found to manage wallets.")


        # --- Activity Log Tab ---
        with tab_activity:
            st.header("Platform Activity Log")
            activity_logs = get_all_logs(conn_tabs)
            if activity_logs:
                st.dataframe(pd.DataFrame(activity_logs), use_container_width=True)
            else:
                st.info("No activity logs found.")

        # --- Anomaly Log Tab ---
        with tab_anomaly:
            st.header("Anomaly Detection Log")
            anomaly_logs = get_all_anomalies(conn_tabs)
            if anomaly_logs:
                st.dataframe(pd.DataFrame(anomaly_logs), use_container_width=True)
            else:
                st.info("No anomaly logs found.")

# --- All Reviews Tab ---
        with tab_all_reviews:
            st.header("All Product Reviews")
            all_reviews_data = get_all_reviews(conn_tabs)
            if all_reviews_data:
                reviews_df = pd.DataFrame(all_reviews_data)
                # Display relevant columns, adjust as needed
                st.dataframe(reviews_df[['id', 'product_name', 'buyer_email', 'rating', 'text', 'review_date']], use_container_width=True)
            else:
                st.info("No reviews found.")
# --- All Customer Tickets Tab ---
        with tab_all_tickets:
            st.header("All Customer Support Tickets")
            all_tickets_data = get_all_customer_tickets(conn_tabs)
            if all_tickets_data:
                tickets_df = pd.DataFrame(all_tickets_data)
                # Display relevant columns, adjust as needed
                st.dataframe(tickets_df[['id', 'buyer_email', 'subject', 'status', 'created_at', 'order_id']], use_container_width=True)
            else:
                st.info("No customer support tickets found.")
        # Close the connection used for fetching tab data
        if conn_tabs and conn_tabs.is_connected():
            conn_tabs.close()
    elif st.session_state.role == 'seller':
        # --- Seller Dashboard ---
        conn_seller_init = get_db_connection() # Initial connection for blacklist check
        if not conn_seller_init:
            st.error("Database connection failed. Cannot load Seller Dashboard.")
            st.stop()

        # 1. Blacklist Check (at the very beginning)
        is_blacklisted = False
        try:
            is_blacklisted = check_blacklist(conn_seller_init, st.session_state.user_id)
        except mysql.connector.Error as err:
            st.error(f"Error checking blacklist status: {err}")
            if conn_seller_init and conn_seller_init.is_connected(): conn_seller_init.close()
            st.stop()
        finally:
             # Close the initial connection after the check
             if conn_seller_init and conn_seller_init.is_connected():
                 conn_seller_init.close()

        if is_blacklisted:
            st.error("You are currently blacklisted and cannot perform actions.")
            st.stop() # Stop execution for blacklisted sellers

        st.title("Seller Dashboard")

        # --- Helper Functions (Specific to Seller Role) ---

        @st.cache_data(ttl=60) # Cache seller products for 1 minute
        def get_seller_products(_seller_id):
            """Fetches products listed by a specific seller."""
            products = []
            conn = None
            try:
                conn = get_db_connection()
                if not conn: raise Exception("DB connection failed")
                with conn.cursor(dictionary=True) as cursor:
                    query = """
                        SELECT id, name, price_cents, quantity, created_at
                        FROM Product
                        WHERE seller_id = %s
                        ORDER BY created_at DESC
                    """
                    cursor.execute(query, (_seller_id,))
                    products = cursor.fetchall()
            except Exception as e:
                st.error(f"Error fetching seller products: {e}")
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
                if not conn: raise Exception("DB connection failed")
                with conn.cursor(dictionary=True) as cursor:
                    query = """
                        SELECT t.id, p.name as product_name, u_buyer.email as buyer_email,
                               t.amount_cents, t.timestamp
                        FROM Transaction t
                        JOIN Product p ON t.product_id = p.id
                        JOIN User u_buyer ON t.buyer_id = u_buyer.id
                        WHERE t.seller_id = %s
                        ORDER BY t.timestamp DESC
                    """
                    cursor.execute(query, (_seller_id,))
                    transactions = cursor.fetchall()
            except Exception as e:
                st.error(f"Error fetching seller transactions: {e}")
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
                if not conn: raise Exception("DB connection failed")
                with conn.cursor(dictionary=True) as cursor:
                    query = """
                        SELECT r.id, p.name as product_name, u_buyer.email as buyer_email,
                               r.rating, r.text, r.created_at as review_date
                        FROM Review r
                        JOIN Product p ON r.product_id = p.id
                        JOIN User u_buyer ON r.buyer_id = u_buyer.id
                        WHERE p.seller_id = %s
                        ORDER BY r.created_at DESC
                    """
                    cursor.execute(query, (_seller_id,))
                    reviews = cursor.fetchall()
            except Exception as e:
                st.error(f"Error fetching seller reviews: {e}")
            finally:
                if conn and conn.is_connected():
                    conn.close()
            return reviews

        # --- Seller UI Tabs ---
        tab1, tab2, tab3 = st.tabs(["Manage Products", "View Transactions", "View Reviews"])

        with tab1:
            st.header("Manage Your Products")

            # Display Seller's Products
            st.subheader("My Products")
            seller_products = get_seller_products(st.session_state.user_id)
            if seller_products:
                df_products = pd.DataFrame(seller_products)
                # Format price for display
                df_products['price'] = df_products['price_cents'].apply(lambda x: f"₹{x / 100:.2f}")
                # Format date
                df_products['created_at'] = pd.to_datetime(df_products['created_at']).dt.strftime('%Y-%m-%d %H:%M')
                # Select and reorder columns for display
                st.dataframe(df_products[['id', 'name', 'price', 'quantity', 'created_at']])
            else:
                st.info("You haven't added any products yet.")

            st.divider()

            # Add New Product Form
            st.subheader("Add New Product")
            with st.form("add_product_form", clear_on_submit=True):
                product_name = st.text_input("Product Name*")
                product_desc = st.text_area("Description")
                product_price = st.number_input("Price (₹)*", min_value=0.01, format="%.2f", step=0.50)
                product_quantity = st.number_input("Quantity*", min_value=0, step=1)
                submitted = st.form_submit_button("Add Product")

                if submitted:
                    add_prod_conn = None
                    try:
                        add_prod_conn = get_db_connection()
                        if not add_prod_conn: raise Exception("DB connection failed")

                        # Re-check blacklist before action
                        if check_blacklist(add_prod_conn, st.session_state.user_id):
                            st.error("Action failed: Your account is blacklisted.")
                        elif not product_name:
                            st.warning("Product Name is required.")
                        elif product_price <= 0:
                             st.warning("Price must be positive.")
                        elif product_quantity < 0:
                             st.warning("Quantity cannot be negative.")
                        else:
                            # Convert price to cents
                            price_cents = int(product_price * 100)

                            cursor = add_prod_conn.cursor()
                            insert_sql = """
                                INSERT INTO Product (seller_id, name, description, price_cents, quantity, created_at)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """
                            # New products might need admin approval depending on rules
                            values = (st.session_state.user_id, product_name, product_desc, price_cents, product_quantity, datetime.now())
                            cursor.execute(insert_sql, values)
                            product_id = cursor.lastrowid
                            add_prod_conn.commit()
                            cursor.close()

                            # Log activity
                            log_activity(add_prod_conn, st.session_state.user_id, 'add_product', f'Product ID: {product_id}, Name: {product_name}')

                            st.success(f"Product '{product_name}' added successfully (ID: {product_id})!")
                            st.cache_data.clear() # Clear cache to show new product
                            st.rerun() # Rerun to update the product list

                    except mysql.connector.Error as err:
                        if add_prod_conn: add_prod_conn.rollback()
                        st.error(f"Database error adding product: {err}")
                    except Exception as e:
                        st.error(f"Error adding product: {e}")
                    finally:
                        if add_prod_conn and add_prod_conn.is_connected():
                            add_prod_conn.close()

            # Placeholder for Update/Delete functionality (more complex UI needed)
            # st.subheader("Update/Delete Product")
            # st.info("Update/Delete functionality coming soon.")


        with tab2:
            st.header("View Transactions")
            seller_transactions = get_seller_transactions(st.session_state.user_id)
            if seller_transactions:
                df_transactions = pd.DataFrame(seller_transactions)
                # Format amount
                df_transactions['amount'] = df_transactions['amount_cents'].apply(lambda x: f"₹{x / 100:.2f}") # Use correct column name
                # Format date (using timestamp from query) and rename for display
                df_transactions['transaction_date'] = pd.to_datetime(df_transactions['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                # Select and reorder columns (removed quantity, status)
                st.dataframe(df_transactions[['id', 'product_name', 'buyer_email', 'amount', 'transaction_date']])
            else:
                st.info("No transactions found for your products yet.")


        with tab3:
            st.header("View Product Reviews")
            print(f"DEBUG: Fetching reviews for seller_id: {st.session_state.user_id}") # DEBUG PRINT
            seller_reviews = get_seller_reviews(st.session_state.user_id)
            print(f"DEBUG: Fetched reviews: {seller_reviews}") # DEBUG PRINT
            if seller_reviews:
                df_reviews = pd.DataFrame(seller_reviews)
                 # Format date
                df_reviews['review_date'] = pd.to_datetime(df_reviews['review_date']).dt.strftime('%Y-%m-%d %H:%M:%S')
                # Select and reorder columns
                st.dataframe(df_reviews[['id', 'product_name', 'buyer_email', 'rating', 'text', 'review_date']])
            else:
                st.info("No reviews found for your products yet.")
    elif st.session_state.role == 'buyer':
        # --- Buyer Dashboard ---
        conn = get_db_connection()
        if not conn:
            st.error("Database connection failed. Please try again later.")
            st.stop()

        # 1. Blacklist Check (at the very beginning)
        is_blacklisted = False
        try:
            is_blacklisted = check_blacklist(conn, st.session_state.user_id)
        except mysql.connector.Error as err:
            st.error(f"Error checking blacklist status: {err}")
            # Decide if we should stop execution or allow limited access
            # For now, let's stop if we can't verify blacklist status
            if conn and conn.is_connected():
                conn.close()
            st.stop()

        if is_blacklisted:
            st.error("You are currently blacklisted and cannot perform actions.")
            if conn and conn.is_connected():
                conn.close()
            st.stop()
        def get_user_email(conn_db, user_id_to_fetch):
            """Fetches a user's email by their ID."""
            cursor_email = None
            try:
                cursor_email = conn_db.cursor(dictionary=True)
                cursor_email.execute("SELECT email FROM User WHERE id = %s", (user_id_to_fetch,))
                user_data_email = cursor_email.fetchone()
                if user_data_email:
                    return user_data_email['email']
            except mysql.connector.Error as err_email:
                st.error(f"Error fetching user email: {err_email}")
            finally:
                if cursor_email:
                    cursor_email.close()
            return None

        buyer_email_str = get_user_email(conn, st.session_state.user_id)
        buyer_dashboard_title = "Buyer Dashboard" # Default title
        if buyer_email_str and buyer_email_str.startswith('buyer') and '@example.com' in buyer_email_str:
            try:
                # Extracts 'N' from 'buyerN@example.com'
                buyer_number_str = buyer_email_str.replace('buyer', '').split('@')[0]
                if buyer_number_str.isdigit():
                    buyer_dashboard_title = f"Buyer {buyer_number_str} Dashboard"
            except Exception:
                pass # Stick to default title if parsing fails
        
        st.title(buyer_dashboard_title)
        # Close connection if only used for blacklist check initially
        # However, we'll likely need it again, so keep it open for now,
        # but ensure it's closed properly in all execution paths.

        # 2. Initialize Cart
        if 'cart' not in st.session_state:
            st.session_state.cart = {} # {product_id: quantity}

        # --- Helper Functions (Specific to Buyer Role) ---

        @st.cache_data(ttl=60) # Cache for 1 minute
        def get_products(_conn):
            """Fetches available products from the database."""
            products = []
            try:
                with _conn.cursor(dictionary=True) as cursor:
                    # Join with User table to get seller email
                    query = """
                        SELECT p.id, p.name, p.description, p.price_cents, p.quantity, p.seller_id, u.email as seller_email
                        FROM Product p
                        JOIN User u ON p.seller_id = u.id
                        WHERE p.quantity > 0
                    """
                    cursor.execute(query)
                    products = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching products: {err}")
            return products

        @st.cache_data(ttl=30) # Cache balance for 30 seconds
        def get_wallet_balance(_conn, user_id):
            """Queries Wallet table, returns balance_cents."""
            balance = 0
            try:
                with _conn.cursor(dictionary=True) as cursor:
                    cursor.execute("SELECT balance_cents FROM Wallet WHERE user_id = %s", (user_id,))
                    result = cursor.fetchone()
                    if result:
                        balance = result['balance_cents']
            except mysql.connector.Error as err:
                st.error(f"Error fetching wallet balance: {err}")
                # Handle error appropriately, maybe return None or raise exception
            return balance

        def update_wallet_balance(_conn, user_id, amount_change_cents):
            """Updates Wallet set balance_cents = balance_cents + amount_change_cents."""
            try:
                with _conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE Wallet SET balance_cents = balance_cents + %s WHERE user_id = %s",
                        (amount_change_cents, user_id)
                    )
                # No commit here, assuming it's part of a larger transaction
                return True
            except mysql.connector.Error as err:
                st.error(f"Error updating wallet balance: {err}")
                return False

        @st.cache_data(ttl=60)
        def get_buyer_orders(_conn, user_id):
            """Fetches orders from Order table for the user."""
            orders = []
            try:
                with _conn.cursor(dictionary=True) as cursor:
                    # Join with Payment to show payment status/details if needed
                    query = """
                        SELECT o.id, o.created_at as order_date, o.total_amount_cents, p.timestamp as payment_timestamp
                        FROM `Order` o
                        LEFT JOIN Payment p ON o.payment_id = p.id
                        WHERE o.user_id = %s
                        ORDER BY o.created_at DESC
                    """
                    cursor.execute(query, (user_id,))
                    orders = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching orders: {err}")
            return orders

        @st.cache_data(ttl=60)
        def get_order_products_for_review(_conn, user_id):
            """Fetches products from transactions linked to the user's completed orders
               for which a review doesn't already exist."""
            items = []
            try:
                with _conn.cursor(dictionary=True) as cursor:
                    # Find transactions for the user's orders where a review doesn't exist
                    # Assumes Payment status 'completed' means order is reviewable
                    query = """
                        SELECT t.id as transaction_id, t.product_id, p.name as product_name # Removed o.id, o.created_at
                        FROM Transaction t
                        JOIN Product p ON t.product_id = p.id
                        # JOIN `Order` o ON t.order_id = o.id # REMOVED INVALID JOIN
                        # JOIN Payment pay ON o.payment_id = pay.id # REMOVED INVALID JOIN
                        LEFT JOIN Review r ON t.product_id = r.product_id AND t.buyer_id = r.buyer_id # Simplified join condition, removed o.id
                        WHERE t.buyer_id = %s
                          # AND pay.status = 'completed' # Removed condition
                          AND r.id IS NULL # Keep check for existing review based on product/buyer
                        ORDER BY t.timestamp DESC, p.name ASC # Order by transaction time instead
                    """
                    cursor.execute(query, (user_id,))
                    items = cursor.fetchall()
            except mysql.connector.Error as err:
                st.error(f"Error fetching items for review: {err}")
            return items

        def get_product_details(_conn, product_id):
             """Fetches details for a single product."""
             try:
                 with _conn.cursor(dictionary=True) as cursor:
                     cursor.execute("SELECT name, price_cents, quantity, seller_id FROM Product WHERE id = %s", (product_id,))
                     return cursor.fetchone()
             except mysql.connector.Error as err:
                 st.error(f"Error fetching product details: {err}")
                 return None

        # --- Checkout Logic ---
        def handle_checkout():
            checkout_conn = None # Use a separate connection variable for clarity
            try:
                checkout_conn = get_db_connection()
                if not checkout_conn:
                    st.error("Checkout failed: Could not connect to database.")
                    return

                # Re-check blacklist just before transaction
                if check_blacklist(checkout_conn, st.session_state.user_id):
                    st.error("Checkout failed: Your account is blacklisted.")
                    return

                if not st.session_state.cart:
                    st.warning("Your cart is empty.")
                    return

                total_amount_cents = 0
                product_details_cache = {} # Cache details to avoid multiple queries

                # Calculate total and fetch product details
                for product_id, quantity in st.session_state.cart.items():
                    details = get_product_details(checkout_conn, product_id)
                    if not details:
                        st.error(f"Checkout failed: Could not retrieve details for product ID {product_id}.")
                        return
                    if details['quantity'] < quantity:
                         st.error(f"Checkout failed: Not enough stock for {details['name']} (requested {quantity}, available {details['quantity']}).")
                         return
                    product_details_cache[product_id] = details
                    total_amount_cents += details['price_cents'] * quantity

                # Check buyer's balance
                buyer_balance = get_wallet_balance(checkout_conn, st.session_state.user_id)
                if buyer_balance < total_amount_cents:
                    st.error(f"Insufficient funds. Your balance: ₹{buyer_balance / 100:.2f}, Required: ₹{total_amount_cents / 100:.2f}")
                    return

                # --- Database Transaction ---
                # Manually control autocommit for this block
                original_autocommit_state = checkout_conn.autocommit
                checkout_conn.autocommit = False
                order_id = None
                payment_id = None
                cursor = None # Define cursor outside try to close in finally

                try:
                    cursor = checkout_conn.cursor(dictionary=True) # Use one cursor for the transaction

                    # 1. Create Order
                    order_sql = "INSERT INTO `Order` (user_id, created_at, total_amount_cents) VALUES (%s, %s, %s)"
                    order_values = (st.session_state.user_id, datetime.now(), total_amount_cents)
                    cursor.execute(order_sql, order_values)
                    order_id = cursor.lastrowid
                    if not order_id: raise Exception("Failed to create order record.")

                    # 2. Create Payment record
                    payment_sql = "INSERT INTO Payment (order_id, amount_cents, timestamp) VALUES (%s, %s, %s)"
                    payment_values = (order_id, total_amount_cents, datetime.now())
                    cursor.execute(payment_sql, payment_values)
                    payment_id = cursor.lastrowid
                    if not payment_id: raise Exception("Failed to create payment record.")

                    # 3. Update Order with Payment ID
                    update_order_sql = "UPDATE `Order` SET payment_id = %s WHERE id = %s"
                    cursor.execute(update_order_sql, (payment_id, order_id))
                    if cursor.rowcount == 0: raise Exception("Failed to link payment to order.")

                    # 4. Process each item in the cart
                    for product_id, quantity in st.session_state.cart.items():
                        details = product_details_cache[product_id] # Use cached details
                        price_cents = details['price_cents']
                        seller_id = details['seller_id']
                        item_total_cents = price_cents * quantity

                        # 4a. Double-check Product Quantity (lock might be better in high concurrency)
                        cursor.execute("SELECT quantity FROM Product WHERE id = %s FOR UPDATE", (product_id,)) # Lock row
                        current_quantity = cursor.fetchone()['quantity']
                        if current_quantity < quantity:
                            raise Exception(f"Stock level changed for product ID {product_id}. Checkout aborted.")

                        # 4b. Create Transaction record
                        trans_sql = """
                            INSERT INTO Transaction (buyer_id, seller_id, product_id, amount_cents, timestamp)
                            VALUES (%s, %s, %s, %s, %s)
                        """
                        trans_values = (st.session_state.user_id, seller_id, product_id, item_total_cents, datetime.now())
                        cursor.execute(trans_sql, trans_values)
                        transaction_id = cursor.lastrowid
                        if not transaction_id: raise Exception(f"Failed to create transaction record for product ID {product_id}.")

                        # 4c. Run Fraud Checks for the transaction
                        fraud_check_payload = {
                            'transaction_id': transaction_id,
                            'order_id': order_id,
                            'buyer_id': st.session_state.user_id,
                            'seller_id': seller_id,
                            'product_id': product_id,
                            'quantity': quantity,
                            'amount_cents': item_total_cents
                        }
                        run_fraud_checks(checkout_conn, 'new_transaction', fraud_check_payload)
                        # Check results of fraud checks if they return actionable flags

                        # 4d. Update Product Quantity
                        update_prod_sql = "UPDATE Product SET quantity = quantity - %s WHERE id = %s"
                        cursor.execute(update_prod_sql, (quantity, product_id))
                        if cursor.rowcount == 0: raise Exception(f"Failed to update quantity for product ID {product_id}.")

                        # 4e. Update Seller Wallet (Optional: could be done later/batch)
                        if not update_wallet_balance(checkout_conn, seller_id, item_total_cents):
                             raise Exception(f"Failed to update seller {seller_id} wallet.")


                    # 5. Update Buyer Wallet
                    if not update_wallet_balance(checkout_conn, st.session_state.user_id, -total_amount_cents):
                        raise Exception("Failed to update buyer wallet.")

                    # 6. Update Payment Status to 'completed' (Schema does not have status for Payment)
                    # update_payment_sql = "UPDATE Payment SET status = %s WHERE id = %s"
                    # cursor.execute(update_payment_sql, ('completed', payment_id))
                    # if cursor.rowcount == 0: raise Exception("Failed to update payment status.")

                     # 7. Update Order Status to 'completed' (Schema does not have status for Order)
                    # update_order_status_sql = "UPDATE `Order` SET status = %s WHERE id = %s"
                    # cursor.execute(update_order_status_sql, ('completed', order_id))
                    # if cursor.rowcount == 0: raise Exception("Failed to update order status.")


                    # --- If all steps successful ---
                    checkout_conn.commit()
                    # Log successful checkout (before cursor close, after commit)
                    log_activity(checkout_conn, st.session_state.user_id, 'checkout_success', f'Order ID: {order_id}, Amount: {total_amount_cents}')

                    # Clear the cart
                    st.session_state.cart = {}

                    st.success(f"Order placed successfully! Order ID: {order_id}")
                    st.balloons()
                    st.cache_data.clear() # Clear cache to ensure order list updates
                    st.rerun() # Rerun to clear cart display and update orders

                except Exception as e:
                    checkout_conn.rollback()
                    st.error(f"Checkout failed: {e}")
                    # Log failed checkout attempt (before cursor close, after rollback)
                    log_activity(checkout_conn, st.session_state.user_id, 'checkout_failed', f'Error: {str(e)}')
                finally:
                    if cursor: # Removed 'not cursor.closed' check
                        cursor.close()
                    checkout_conn.autocommit = original_autocommit_state # Restore autocommit

            except mysql.connector.Error as db_err:
                 st.error(f"Database error during checkout: {db_err}")
                 # Attempt to log DB error if possible
                 if checkout_conn:
                     try:
                         log_activity(checkout_conn, st.session_state.user_id, 'checkout_failed', f'DB Error: {str(db_err)}')
                         if checkout_conn.is_connected() and not original_autocommit_state: # If we changed autocommit, try to restore
                             checkout_conn.autocommit = original_autocommit_state
                     except: pass # Avoid error loops
            finally:
                # Ensure connection is closed and autocommit is restored if changed
                if checkout_conn and checkout_conn.is_connected():
                    if hasattr(locals(), 'original_autocommit_state') and checkout_conn.autocommit != original_autocommit_state:
                        try:
                            checkout_conn.autocommit = original_autocommit_state
                        except: pass # Best effort
                    checkout_conn.close()


        # --- Main Buyer UI ---
        st.title("Buyer Dashboard")

        # Display Wallet Balance
        buyer_conn_wallet = get_db_connection()
        if buyer_conn_wallet:
            current_balance_cents = get_wallet_balance(buyer_conn_wallet, st.session_state.user_id)
            st.metric("My Wallet Balance", f"₹{current_balance_cents / 100:.2f}")
            if buyer_conn_wallet.is_connected():
                buyer_conn_wallet.close()
        else:
            st.warning("Could not fetch wallet balance.")


        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "Browse Products", "View Cart", "My Orders", "Submit Review", "Customer Support"
        ])

        with tab1:
            st.header("Browse Products")
            products = get_products(conn) # Use the main connection

            if not products:
                st.info("No products currently available.")
            else:
                # Display products - using columns for better layout
                cols = st.columns(3) # Adjust number of columns as needed
                col_idx = 0
                for product in products:
                    with cols[col_idx % len(cols)]:
                        with st.container(border=True):
                            st.subheader(product['name'])
                            st.caption(f"Seller: {product['seller_email']}")
                            st.write(product.get('description', 'No description available.'))
                            st.metric(label="Price", value=f"₹{product['price_cents'] / 100:.2f}")
                            st.metric(label="Available Quantity", value=product['quantity'])

                            add_button_key = f"add_{product['id']}"
                            if st.button(f"Add to Cart", key=add_button_key):
                                add_conn = None # Connection for this specific action
                                try:
                                    add_conn = get_db_connection()
                                    if not add_conn: raise Exception("DB connection failed")

                                    # Re-check blacklist
                                    if check_blacklist(add_conn, st.session_state.user_id):
                                        st.error("Action failed: Your account is blacklisted.")
                                    else:
                                        # Get current product details (especially quantity)
                                        prod_details = get_product_details(add_conn, product['id'])
                                        if prod_details and prod_details['quantity'] > 0:
                                            # Add/increment product in cart
                                            current_cart_qty = st.session_state.cart.get(product['id'], 0)
                                            if current_cart_qty < prod_details['quantity']:
                                                st.session_state.cart[product['id']] = current_cart_qty + 1

                                                # Log activity
                                                log_activity(add_conn, st.session_state.user_id, 'cart_add', f'Product ID: {product["id"]}')

                                                # Run fraud check for cart action
                                                run_fraud_checks(add_conn, 'cart_action', {'user_id': st.session_state.user_id, 'product_id': product['id'], 'action': 'add'})
                                                # Note: check_cart_flapping needs implementation in fraud_detection.py

                                                st.success(f"Added {product['name']} to cart.")
                                                # No rerun needed here, cart updates implicitly
                                            else:
                                                 st.warning(f"Cannot add more {product['name']}. Max available quantity reached in cart.")
                                        else:
                                            st.error(f"Could not add {product['name']} to cart. Item might be out of stock.")
                                            # Optionally remove from display if quantity hit 0? Requires rerun.

                                except Exception as e:
                                    st.error(f"Error adding to cart: {e}")
                                finally:
                                     if add_conn and add_conn.is_connected():
                                         add_conn.close()
                    col_idx += 1


        with tab2:
            st.header("View Cart")
            if not st.session_state.cart:
                st.info("Your cart is empty.")
            else:
                cart_items_details = []
                total_cart_amount_cents = 0
                cart_conn = None
                try:
                    cart_conn = get_db_connection()
                    if not cart_conn: raise Exception("DB connection failed")

                    for product_id, quantity in st.session_state.cart.items():
                        details = get_product_details(cart_conn, product_id) # Fetch fresh details
                        if details:
                            item_total = details['price_cents'] * quantity
                            cart_items_details.append({
                                "Product ID": product_id,
                                "Name": details['name'],
                                "Quantity": quantity,
                                "Price per Item": f"₹{details['price_cents'] / 100:.2f}",
                                "Total": f"₹{item_total / 100:.2f}",
                                "_price_cents": details['price_cents'] # Keep numeric for calculation
                            })
                            total_cart_amount_cents += item_total
                        else:
                            # Handle case where product details couldn't be fetched (e.g., removed)
                            st.warning(f"Could not load details for product ID {product_id} in cart. It might have been removed.")
                            # Optionally remove from cart here: del st.session_state.cart[product_id] and rerun

                    if cart_items_details:
                        st.dataframe(pd.DataFrame(cart_items_details).drop(columns=['_price_cents'])) # Display nice table
                        st.subheader(f"Total Cart Amount: ₹{total_cart_amount_cents / 100:.2f}")

                        if st.button("Checkout"):
                            handle_checkout() # Call the checkout function
                    else:
                         st.info("Your cart is empty or contains unavailable items.")


                except Exception as e:
                    st.error(f"Error displaying cart: {e}")
                finally:
                    if cart_conn and cart_conn.is_connected():
                        cart_conn.close()


        with tab3:
            st.header("My Orders")
            orders_conn = None
            try:
                orders_conn = get_db_connection()
                if not orders_conn: raise Exception("DB connection failed")
                buyer_orders = get_buyer_orders(orders_conn, st.session_state.user_id)
                if buyer_orders:
                    df_orders = pd.DataFrame(buyer_orders)
                    # Format currency and dates for display
                    df_orders['total_amount_cents'] = df_orders['total_amount_cents'].apply(lambda x: f"₹{x / 100:.2f}")
                    df_orders['order_date'] = pd.to_datetime(df_orders['order_date']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    df_orders['payment_timestamp'] = pd.to_datetime(df_orders['payment_timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    st.dataframe(df_orders)
                else:
                    st.info("You have not placed any orders yet.")
            except Exception as e:
                 st.error(f"Error fetching orders: {e}")
            finally:
                if orders_conn and orders_conn.is_connected():
                    orders_conn.close()


        with tab4:
            st.header("Submit Review")
            review_conn = None
            try:
                review_conn = get_db_connection()
                if not review_conn: raise Exception("DB connection failed")

                items_to_review = get_order_products_for_review(review_conn, st.session_state.user_id)

                if not items_to_review:
                    st.info("No items currently available for review.")
                else:
                    # Removed order_id from display string as it's not reliably available
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


        with tab5:
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

        # Ensure the main connection for the buyer dashboard is closed if open
        # This is tricky because helper functions might use it.
        # A better approach might be to open/close connections within each tab/action
        # or use a context manager if Streamlit supported it well across reruns.
        # For now, relying on connections being closed within specific actions/tabs.
        # The initial 'conn' might remain open if no tab explicitly closes it.
        # Let's try closing it here, but this might cause issues if cached functions rely on it.
        # A safer bet is ensuring each tab/action manages its own connection lifecycle.
        # Commenting out the close here as it might break cached functions.
        # if conn and conn.is_connected():
        #     conn.close()

    else:
        st.error("Unknown role assigned. Please contact support.")

# Example usage of the DB connection (can be removed later)
# conn = get_db_connection()
# if conn:
#     st.success("Successfully connected to the database (cached).")
#     # Remember to close the connection when done if not managed by Streamlit's caching context
#     # conn.close() # Be careful with closing cached resources prematurely
# else:
#     st.warning("Could not establish database connection.")