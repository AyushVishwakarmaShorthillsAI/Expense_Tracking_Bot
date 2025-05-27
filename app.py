import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import os
import re
import time
import uuid  # Added for token generation
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain_cohere import ChatCohere
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv
import dateparser
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
from supabase import create_client, Client
import bcrypt
from langchain.agents import create_sql_agent
from langchain.agents.agent_toolkits import SQLDatabaseToolkit
from langchain_community.utilities import SQLDatabase
from sqlalchemy import create_engine
import urllib.parse
import psycopg2
from datetime import timezone

# --- Database Setup (Supabase) ---
SUPABASE_URL = st.secrets.get("supabase", {}).get("url")
SUPABASE_KEY = st.secrets.get("supabase", {}).get("key")

if not SUPABASE_URL or not SUPABASE_KEY:
    st.error("Supabase URL and Key not found in secrets. Please add them.")
    st.stop()

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def get_user_expenses(user_id):
    """Fetches expenses for the given user_id from Supabase without caching, sorted by date and time."""
    try:
        response = supabase.table('expense')\
                         .select("date", "time", "category", "amount", "month", "description")\
                         .eq('user_id', user_id)\
                         .order('date', desc=True)\
                         .order('time', desc=True)\
                         .execute()

        if response.data:
            df = pd.DataFrame(response.data)
            df['date'] = pd.to_datetime(df['date']).dt.date
            df['amount'] = pd.to_numeric(df['amount'])
            print(f"Fetched {len(df)} expenses for user_id: {user_id} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Most recent expense: {df.iloc[0].to_dict() if not df.empty else 'None'}")
            return df
        else:
            print(f"No expenses found for user_id: {user_id} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            return pd.DataFrame(columns=["date", "time", "category", "amount", "month", "description"])
    except Exception as e:
        st.error(f"Error fetching expenses from Supabase: {e}")
        return pd.DataFrame(columns=["date", "time", "category", "amount", "month", "description"])

def check_duplicate_expense(user_id, expense_data):
    """Checks if the most recent expense for the user has the same amount and category."""
    try:
        response = supabase.table('expense')\
                           .select("category", "amount")\
                           .eq('user_id', user_id)\
                           .order('date', desc=True)\
                           .order('time', desc=True)\
                           .limit(1)\
                           .execute()

        if response.data and len(response.data) > 0:
            previous_expense = response.data[0]
            is_duplicate = (previous_expense['category'] == expense_data['category'] and
                           previous_expense['amount'] == expense_data['amount'])
            print(f"Checked duplicate for user_id: {user_id}. New expense: {expense_data['category']}, ₹{expense_data['amount']}. "
                  f"Previous expense: {previous_expense['category']}, ₹{previous_expense['amount']}. "
                  f"Duplicate: {is_duplicate}")
            return is_duplicate
        return False
    except Exception as e:
        st.error(f"Error checking for duplicate expense: {e}")
        return False

def add_expense_db(user_id, data):
    """Inserts a new expense record into the Supabase DB."""
    try:
        data_to_insert = data.copy()
        data_to_insert['user_id'] = user_id
        data_to_insert['date'] = data['date'].strftime('%Y-%m-%d')

        response = supabase.table('expense').insert(data_to_insert).execute()

        if response.data and len(response.data) > 0:
            print(f"Successfully added expense for user_id: {user_id} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: {data_to_insert}")
            return True
        elif hasattr(response, 'error') and response.error:
            st.error(f"Failed to add expense: {response.error.message}")
            print(f"Supabase Insert Error: {response.error}")
            return False
        else:
            st.error(f"Failed to add expense. Unexpected response: {response}")
            print(f"Supabase Insert Response (Unknown Structure): {response}")
            return False
    except Exception as e:
        st.error(f"Error adding expense to Supabase: {type(e).__name__}: {e}")
        import traceback
        print(traceback.format_exc())
        return False

def get_users_for_authenticator():
    """Fetches user credentials for streamlit-authenticator."""
    try:
        response = supabase.table('users').select('username', 'name', 'password').execute()
        if response.data:
            users_dict = {'usernames': {}}
            for user in response.data:
                users_dict['usernames'][user['username']] = {
                    'name': user['name'],
                    'password': user['password']
                }
            return users_dict
        else:
            return {'usernames': {}}
    except Exception as e:
        st.error(f"Error fetching users for authenticator init: {e}")
        return {'usernames': {}}

def get_user_login_info(username: str):
    """Fetches name and hashed password for a specific user."""
    try:
        response = supabase.table('users')\
                         .select('name', 'password')\
                         .eq('username', username)\
                         .maybe_single()\
                         .execute()
        if response.data:
            return response.data
        else:
            return None
    except Exception as e:
        st.error(f"Error fetching user login info for {username}: {e}")
        return None

def get_user_by_token(token: str):
    """Fetches user info by token from the users table."""
    try:
        print(f"Querying Supabase for token: {token}")
        response = supabase.table('users')\
                         .select('username', 'name')\
                         .eq('token', token)\
                         .maybe_single()\
                         .execute()
        if response.data:
            print(f"Found user for token {token}: {response.data}")
            return response.data
        else:
            print(f"No user found for token: {token}")
            return None
    except Exception as e:
        st.error(f"Error fetching user by token: {e}")
        print(f"Exception in get_user_by_token: {e}")
        return None

def set_user_token(username: str, token: str, expiry_days: int = 1):
    """Stores the token and expiry timestamp for the user in Supabase."""
    try:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expiry_days)
        response = supabase.table('users')\
                           .update({'token': token, 'expires_at': expires_at.isoformat()})\
                           .eq('username', username)\
                           .execute()
        if response.data:
            print(f"Stored token for {username}: {token}, expires at: {expires_at}")
        else:
            print(f"Failed to store token for {username}")
    except Exception as e:
        print(f"Error storing token in Supabase: {e}")

def get_user_token(username: str):
    """Retrieves the user's token from Supabase if it hasn't expired."""
    try:
        now = datetime.now(timezone.utc)
        response = supabase.table('users')\
                           .select('token', 'expires_at')\
                           .eq('username', username)\
                           .maybe_single()\
                           .execute()
        if response.data and response.data['token']:
            expires_at = datetime.fromisoformat(response.data['expires_at'])
            if now < expires_at:
                print(f"Found valid token for {username}: {response.data['token']}")
                return response.data['token']
            else:
                print(f"Token for {username} has expired at {expires_at}")
                # Clear expired token
                supabase.table('users')\
                        .update({'token': None, 'expires_at': None})\
                        .eq('username', username)\
                        .execute()
        print(f"No valid token found for {username}")
        return None
    except Exception as e:
        print(f"Error retrieving token from Supabase: {e}")
        return None

def clear_user_token(username: str):
    """Clears the user's token from Supabase."""
    try:
        response = supabase.table('users')\
                           .update({'token': None, 'expires_at': None})\
                           .eq('username', username)\
                           .execute()
        print(f"Cleared token for {username}")
    except Exception as e:
        print(f"Error clearing token in Supabase: {e}")

def register_user_db(username, name, hashed_password):
    """Adds a new user to the Supabase 'users' table."""
    try:
        password_to_store = hashed_password.decode('utf-8') if isinstance(hashed_password, bytes) else hashed_password
        response = supabase.table('users').insert({
            'username': username,
            'name': name,
            'password': password_to_store,
            'token': None,
            'expires_at': None  # Initialize expires_at as null
        }).execute()
        if len(response.data) > 0:
            return True
        else:
            st.error(f"Registration failed. Response: {response}")
            return False
    except Exception as e:
        st.error(f"Database error during registration: {e}")
        return False

# --- LLM Setup ---
load_dotenv()
llm = ChatCohere(model="command", temperature=0.2)
prompt = PromptTemplate(
    input_variables=["query"],
    template="""
    You are a helpful assistant. Your task is to process the following request: {query}.
    Extract the following details:
    - Date: Identify any date mentioned in the input (e.g., "2025-04-25", "25 April 2025", "yesterday", "today"). If no date is explicitly mentioned, leave it blank for the system to handle.
    - Amount: Extract the monetary amount (e.g., "120", "₹120").
    - Category: Identify the category if mentioned (e.g., "clothing"). If not mentioned, use "other".

    Respond with a structured output like:
    Date: [date or blank if not mentioned]
    Amount: [number]
    Category: [category]
    """
)
chain = prompt | llm

# --- Utility Functions ---
def parse_llm_output(output, user_input=None):
    if hasattr(output, 'content'):
        output = output.content

    data = {}
    lines = output.strip().split('\n')

    for line in lines:
        if ':' in line:
            key, val = line.split(':', 1)
            data[key.strip().lower()] = val.strip()
        elif any(word.lower() in line.lower() for word in ["amount", "cost", "price"]):
            amount_match = re.search(r'[-+]?\d*\.?\d+', line)
            if amount_match:
                data['amount'] = amount_match.group(0)
        elif any(word.lower() in line.lower() for word in ["date"]):
            date_match = re.search(r'\d{4}-\d{2}-\d{2}', line)
            if date_match:
                data['date'] = date_match.group(0)
            else:
                parsed_date = dateparser.parse(line, settings={'PREFER_DAY_OF_MONTH': 'first', 'RETURN_AS_TIMEZONE_AWARE': False})
                if parsed_date:
                    data['date'] = parsed_date.strftime("%Y-%m-%d")
        elif any(word.lower() in line.lower() for word in ["category"]):
            category_match = re.search(r'(?:category|type|kind)[:\s]*(\S+)', line, re.IGNORECASE)
            if category_match:
                data['category'] = category_match.group(1).lower()

    if 'date' not in data and user_input:
        parsed_date = dateparser.parse(
            user_input,
            settings={'PREFER_DAY_OF_MONTH': 'first', 'RETURN_AS_TIMEZONE_AWARE': False}
        )
        if parsed_date:
            data['date'] = parsed_date.strftime("%Y-%m-%d")

    if 'date' not in data or not data['date']:
        data['date'] = datetime.today().strftime("%Y-%m-%d")
    if 'amount' not in data:
        raw_amount = data.get('amount_raw', '')
        if raw_amount:
            amount_match = re.search(r'[-+]?\d*\.?\d+', raw_amount)
            if amount_match:
                data['amount'] = amount_match.group(0)
        if 'amount' not in data or not data['amount']:
            data['amount'] = "0"
    if 'category' not in data or not data['category']:
        data['category'] = "other"

    data['amount'] = re.sub(r'[^\d.]', '', str(data.get('amount', '0')))
    if not data['amount']:
        data['amount'] = '0'

    return data

def clean_date(raw_date):
    raw_date_str = str(raw_date) if raw_date else ""
    if raw_date_str:
        parsed = dateparser.parse(raw_date_str, settings={'PREFER_DAY_OF_MONTH': 'first'})
        if parsed:
            return parsed.date()
    return datetime.today().date()

def update_excel_data_prep(data):
    expense_date = clean_date(data.get("date", "today"))
    time = datetime.now().strftime("%H:%M:%S")
    amount_str = str(data.get("amount", "0")).replace("₹", "").replace(",", "").strip()
    amount = float(amount_str) if amount_str else 0.0
    category = str(data.get("category", "other")).lower().strip()
    month = expense_date.strftime("%B %Y")
    description = data.get("description", "")
    return {
        "date": expense_date,
        "time": time,
        "category": category,
        "amount": amount,
        "month": month,
        "description": description
    }

# --- SQL Agent Setup ---
def get_db_engine():
    """Creates SQLAlchemy engine for Supabase connection."""
    db_host_raw = st.secrets.get("supabase", {}).get("db_host")
    db_port_secret = st.secrets.get("supabase", {}).get("db_port")
    db_password_raw = st.secrets.get("supabase", {}).get("db_password")

    if not db_host_raw or not db_port_secret or not db_password_raw:
        st.error("Database host, port, or password not found in secrets.")
        return None

    try:
        encoded_password = urllib.parse.quote_plus(db_password_raw)
        encoded_db_host = urllib.parse.quote_plus(db_host_raw)
    except Exception as e:
        st.error(f"Failed to URL-encode database credentials or host: {e}")
        return None

    connection_port = 6543
    connection_string = f"postgresql://postgres.xupvavqdvunalnpxqlxa:{db_password_raw}@{db_host_raw}:6543/postgres"

    try:
        engine = create_engine(connection_string)
        connection = engine.connect()
        connection.close()
        print("Database connection successful!")
        return engine
    except psycopg2.OperationalError as op_err:
        st.error(f"Failed to create database engine (OperationalError): {op_err}")
        return None
    except Exception as e:
        st.error(f"Failed to create database engine: {e}")
        return None

@st.cache_resource
def load_sql_agent_for_user(user_id: str):
    """Loads or creates the SQL agent for the given user."""
    engine = get_db_engine()
    if not engine:
        return None

    db = SQLDatabase(engine, include_tables=['expense'], sample_rows_in_table_info=2)

    sql_prefix = f"""
You are an agent designed to interact with a SQL database containing expense data for multiple users.
Given an input question, create a syntactically correct PostgreSQL query to run, then look at the results of the query and return the answer.
Unless the user specifies a specific number of examples they wish to obtain, always limit your query to at most 10 results.
You can order the results by a relevant column to return the most interesting examples in the database.
Never query for all the columns from a specific table, only ask for the relevant columns given the question.

You have access to the following tables: {db.get_usable_table_names()}

**VERY IMPORTANT**: You MUST filter your query based on the user making the request. The current user's ID is '{user_id}'.
**ALL queries to the 'expense' table MUST include `WHERE user_id = '{user_id}'`**.

For example:
Question: How much did I spend on food last week?
SQLQuery: SELECT sum(amount) FROM expense WHERE category = 'food' AND date >= current_date - interval '7 days' AND user_id = '{user_id}';

Question: Show my last 3 expenses
SQLQuery: SELECT date, category, amount, description FROM expense WHERE user_id = '{user_id}' ORDER BY date DESC, time DESC LIMIT 3;

Only use the following tables: {db.get_usable_table_names()}
"""

    try:
        toolkit = SQLDatabaseToolkit(db=db, llm=llm)
        agent_executor = create_sql_agent(
            llm=llm,
            toolkit=toolkit,
            verbose=True,
            prefix=sql_prefix,
            handle_parsing_errors=True
        )
        return agent_executor
    except Exception as e:
        st.error(f"Failed to create SQL query agent: {e}")
        return None

# --- Streamlit App ---
st.set_page_config(page_title="Expense Tracking Bot", layout="wide")
st.title("💰 Expense Tracking Bot")

# --- JavaScript (Simplified, only for button disabling) ---
st.markdown(
    """
    <script>
    // Disable "Add Expense" button temporarily after submission
    document.addEventListener('DOMContentLoaded', function() {
        const submitButton = document.querySelector('button[kind="formSubmit"]');
        if (submitButton) {
            submitButton.addEventListener('click', function() {
                this.disabled = true;
                setTimeout(() => { this.disabled = false; }, 2000);
            });
        }
    });
    </script>
    """,
    unsafe_allow_html=True
)

# --- Authentication State Initialization ---
if 'authentication_status' not in st.session_state:
    st.session_state['authentication_status'] = None
if 'name' not in st.session_state:
    st.session_state['name'] = None
if 'username' not in st.session_state:
    st.session_state['username'] = None
if 'show_register_form' not in st.session_state:
    st.session_state['show_register_form'] = False
if 'expense_data' not in st.session_state:
    st.session_state['expense_data'] = None
if 'pending_expense' not in st.session_state:
    st.session_state['pending_expense'] = None
if 'show_confirmation' not in st.session_state:
    st.session_state['show_confirmation'] = False
if 'token' not in st.session_state:
    st.session_state['token'] = None

# --- Check for Token and Auto-Login ---
# --- Check for Token and Auto-Login ---
# Try to retrieve the token from Supabase
if not st.session_state.get('authentication_status'):
    try:
        # Query users with a non-null token
        users_with_tokens = supabase.table('users')\
                                    .select('username', 'token', 'expires_at')\
                                    .neq('token', None)\
                                    .execute()
        now = datetime.now(timezone.utc)
        token = None
        username = None
        for user in users_with_tokens.data:
            expires_at_raw = user['expires_at']
            expires_at = None
            if expires_at_raw is None:
                print(f"No expires_at for user {user['username']}, skipping.")
                continue
            # Check if expires_at is already a datetime object
            if isinstance(expires_at_raw, datetime):
                expires_at = expires_at_raw
            else:
                # Assume it's a string and try to parse it
                try:
                    expires_at = datetime.fromisoformat(str(expires_at_raw).replace('Z', '+00:00'))
                except ValueError as e:
                    print(f"Error parsing expires_at for user {user['username']}: {e}, value: {expires_at_raw}")
                    continue
            # Ensure expires_at is timezone-aware
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now < expires_at:
                token = user['token']
                username = user['username']
                break
            else:
                print(f"Token for user {user['username']} expired at {expires_at}, skipping.")
        if token and username:
            st.session_state['token'] = token
            print(f"Retrieved token from Supabase for {username}: {token}")
        else:
            print("No valid token found for auto-login.")
    except Exception as e:
        print(f"Error querying users for auto-login: {e}")
        st.error(f"Failed to check for existing login session: {e}")

# If not logged in, check for token and attempt auto-login
if not st.session_state.get('authentication_status') and st.session_state.get('token'):
    print(f"Attempting auto-login with token: {st.session_state['token']}")
    user_info = get_user_by_token(st.session_state['token'])
    if user_info:
        print(f"Token validation successful. User info: {user_info}")
        st.session_state['authentication_status'] = True
        st.session_state['username'] = user_info['username']
        st.session_state['name'] = user_info['name']
        st.session_state['expense_data'] = None
        st.session_state['pending_expense'] = None
        st.session_state['show_confirmation'] = False
        print(f"Auto-login successful for username: {user_info['username']} using token: {st.session_state['token']}")
        st.rerun()
    else:
        print("Token validation failed. Clearing token.")
        st.session_state['token'] = None
        if username:
            clear_user_token(username)
    
# --- Still use Authenticator for Logout ---
auth_users = get_users_for_authenticator()
authenticator = stauth.Authenticate(
    auth_users,
    "expense_tracker_cookie_bcrypt",
    st.secrets.get("auth", {}).get("authenticator_key", "local_dev_key_bcrypt"),
    1
)

# --- Login/Register Flow Management ---
def go_to_register():
    st.session_state.show_register_form = True

def go_to_login():
    st.session_state.show_register_form = False

def perform_logout():
    if st.session_state.get('username'):
        clear_user_token(st.session_state['username'])
    st.session_state['token'] = None
    authenticator.logout("Logout", "sidebar")
    st.session_state['authentication_status'] = None
    st.session_state['name'] = None
    st.session_state['username'] = None
    st.session_state['expense_data'] = None
    st.session_state['pending_expense'] = None
    st.session_state['show_confirmation'] = False
    st.rerun()

# --- Render Login or Registration View ---
if not st.session_state.get('authentication_status'):
    if not st.session_state.show_register_form:
        st.subheader("Login")
        with st.form("login_form"):
            login_username = st.text_input("Username")
            login_password = st.text_input("Password", type="password")
            login_submitted = st.form_submit_button("Login")

            if login_submitted:
                if not login_username or not login_password:
                    st.error("Please enter username and password.")
                else:
                    user_info = get_user_login_info(login_username)
                    if user_info and 'password' in user_info:
                        stored_hashed_password = user_info['password']
                        if bcrypt.checkpw(login_password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                            # Generate and store token in Supabase
                            token = str(uuid.uuid4())
                            set_user_token(login_username, token, expiry_days=1)
                            st.session_state['token'] = token
                            st.session_state['authentication_status'] = True
                            st.session_state['name'] = user_info.get('name', login_username)
                            st.session_state['username'] = login_username
                            st.session_state['expense_data'] = None
                            st.session_state['pending_expense'] = None
                            st.session_state['show_confirmation'] = False
                            st.rerun()
                        else:
                            st.error("Incorrect username or password.")
                            st.session_state['authentication_status'] = False
                    else:
                        st.error("Incorrect username or password.")
                        st.session_state['authentication_status'] = False

        st.button("New User? Register Here", on_click=go_to_register)

    else:
        st.subheader("Register New User")
        with st.form("register_form", clear_on_submit=True):
            reg_name = st.text_input("Name", key="reg_name")
            reg_username = st.text_input("Username", key="reg_username")
            reg_password = st.text_input("Password", type="password", key="reg_pwd")
            reg_password_repeat = st.text_input("Repeat Password", type="password", key="reg_pwd_repeat")
            register_submitted = st.form_submit_button("Register")

            if register_submitted:
                if not reg_name or not reg_username or not reg_password or not reg_password_repeat:
                    st.error("Please fill in all fields.")
                elif reg_password != reg_password_repeat:
                    st.error("Passwords do not match.")
                else:
                    existing_user = get_user_login_info(reg_username)
                    if existing_user:
                        st.error("Username already exists. Please choose another or login.")
                    else:
                        try:
                            hashed_password_bytes = bcrypt.hashpw(reg_password.encode('utf-8'), bcrypt.gensalt())
                            if register_user_db(reg_username, reg_name, hashed_password_bytes):
                                st.success("Registration successful! Please login.")
                                st.session_state.show_register_form = False
                                st.rerun()
                            else:
                                st.error("Registration failed (database error). Please try again.")
                        except Exception as e:
                            st.error(f"An error occurred during registration: {e}")

        st.button("Back to Login", on_click=go_to_login)

# --- Main App Logic ---
elif st.session_state.get('authentication_status'):
    name = st.session_state.get('name')
    username = st.session_state.get('username')

    st.sidebar.write(f'Welcome *{name}*')
    if st.sidebar.button("Logout"):
        perform_logout()

    page = st.sidebar.selectbox("Navigate", ["Home", "Add Expense", "Query Expenses", "Monthly Summary", "Spending Trends"])
    user_id = username

    if page == "Home":
        st.header(f"{name}'s Dashboard")
        st.session_state['expense_data'] = None
        df_user = get_user_expenses(user_id)
        st.session_state['expense_data'] = df_user
        if not df_user.empty:
            df_user['amount'] = pd.to_numeric(df_user['amount'], errors='coerce').fillna(0.0)
            total_expenses = df_user["amount"].sum()
            st.metric("Total Expenses", f"₹{total_expenses:.2f}")
            st.subheader("Recent Expenses")
            df_display = df_user.copy()
            df_display['date'] = pd.to_datetime(df_display['date'], errors='coerce').dt.strftime('%Y-%m-%d')
            df_display.dropna(subset=['date'], inplace=True)
            display_cols = ["date", "time", "category", "amount", "description"]
            existing_display_cols = [col for col in display_cols if col in df_display.columns]
            df_display_sorted = df_display.sort_values(by=['date', 'time'], ascending=False)
            st.dataframe(df_display_sorted.head(5)[existing_display_cols])
            print(f"Displayed recent expenses: {df_display_sorted.head(5)[existing_display_cols].to_dict('records')}")
            st.subheader("Category-Wise Spending")
            df_user['category'] = df_user['category'].fillna('other').astype(str)
            grouped = df_user.groupby("category")["amount"].sum().reset_index()
            if not grouped.empty and grouped['amount'].sum() > 0:
                fig = px.pie(grouped, values="amount", names="category", title="Spending by Category")
                st.plotly_chart(fig)
            else:
                st.info("No spending data available to display category chart.")
        else:
            st.info("No expenses recorded yet. Go to 'Add Expense' to start tracking.")

    elif page == "Add Expense":
        st.header("Add Expense")
        with st.form("expense_form", clear_on_submit=True):
            expense_input_text = st.text_input("Amount")
            category_override = st.text_input("Category (eg. food, travel, clothing, etc.)")
            description = st.text_area("Description (optional)")
            submitted = st.form_submit_button("Add Expense")

            if submitted:
                if expense_input_text:
                    try:
                        llm_response = chain.invoke({"query": expense_input_text})
                        parsed_data = parse_llm_output(llm_response, user_input=expense_input_text)
                        parsed_data['category'] = category_override.lower().strip() or parsed_data['category']
                        parsed_data['description'] = description
                        expense_record = update_excel_data_prep(parsed_data)

                        if check_duplicate_expense(user_id, expense_record):
                            st.session_state['pending_expense'] = expense_record
                            st.session_state['show_confirmation'] = True
                            st.warning(f"Duplicate expense detected! The most recent expense has the same category ({expense_record['category']}) "
                                       f"and amount (₹{expense_record['amount']}). Do you want to save this expense?")
                        else:
                            if add_expense_db(user_id, expense_record):
                                st.success("Expense saved!")
                                time.sleep(1)
                                st.session_state['pending_expense'] = None
                                st.session_state['show_confirmation'] = False
                                st.rerun()
                            else:
                                pass
                    except Exception as e:
                        st.error(f"Error processing or saving expense: {e}")
                        st.error("Please check your input or try rephrasing.")
                else:
                    st.error("Please enter expense details.")

        if st.session_state.get('show_confirmation', False) and st.session_state.get('pending_expense'):
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Yes, save it"):
                    if add_expense_db(user_id, st.session_state['pending_expense']):
                        st.success("Expense saved!")
                        time.sleep(1)
                        print("User confirmed saving duplicate expense.")
                        st.session_state['pending_expense'] = None
                        st.session_state['show_confirmation'] = False
                        st.rerun()
                    else:
                        st.session_state['pending_expense'] = None
                        st.session_state['show_confirmation'] = False
            with col2:
                if st.button("No, cancel"):
                    st.info("Expense not saved.")
                    print("User cancelled saving duplicate expense.")
                    st.session_state['pending_expense'] = None
                    st.session_state['show_confirmation'] = False
                    st.rerun()

    elif page == "Query Expenses":
        st.header("Query Expenses")
        query = st.text_input("Ask about your expenses (e.g., 'Total spent on food last month?')", key="query_input")

        agent = load_sql_agent_for_user(user_id)

        if agent:
            st.write("### Example Queries:")
            example_queries = [
                "What is the total amount spent on clothing and technology",
                "What is the total amount spent in April 2025",
                "Show all expenses for the month of September 2025",
                "get all the expense with amount greater than 500",
                "fetch all the rows where category is food",
                "fetch all the records with category technology",
                "fetch the names of different categories",
                "Show the most expensive expense",
                "How many expenses are there in each category?",
                "What is the total amount spent on travel"
            ]
            for q in example_queries:
                st.write(f"- {q}")

            if query:
                with st.spinner("Processing your query..."):
                    try:
                        response = agent.invoke({"input": query})
                        answer = response.get('output', "Sorry, I couldn't process that.")
                        st.write("Answer:")
                        st.markdown(answer.strip())
                    except Exception as e:
                        st.error(f"Error querying expenses: {e}")
                        st.warning("The agent might not understand the query or there could be an issue accessing the data. Try rephrasing or check logs.")
        else:
            st.warning("Could not initialize the query agent. Check database connection and secrets.")

    elif page == "Monthly Summary":
        st.header("Monthly Summary")
        df_user = get_user_expenses(user_id)
        if not df_user.empty:
            df_user['month'] = df_user['month'].fillna('').astype(str).str.strip().str.title()
            df_user['category'] = df_user['category'].fillna('other').astype(str).str.strip().str.lower()
            df_user['amount'] = pd.to_numeric(df_user['amount'], errors='coerce').fillna(0.0)
            available_months = sorted(df_user[df_user['month']!='']['month'].unique())
            if not available_months:
                st.warning("No data with valid months found.")
            else:
                month_select = st.selectbox("Select month:", available_months)
                if month_select:
                    summary_df = df_user[df_user['month'] == month_select]
                    if not summary_df.empty:
                        summary = summary_df.groupby('category')['amount'].sum()
                        st.write(f"Spending Summary for {month_select}:")
                        total_month_spending = summary.sum()
                        summary_sorted = summary.sort_values(ascending=False)
                        for category, amount in summary_sorted.items():
                            st.write(f"- {category.capitalize()}: ₹{amount:.2f}")
                        st.write("---")
                        st.write(f"**Total for {month_select}: ₹{total_month_spending:.2f}**")
                        st.write("### Detailed Expenses for ", month_select)
                        df_display = summary_df.copy()
                        df_display['date'] = pd.to_datetime(df_display['date'], errors='coerce').dt.strftime('%Y-%m-%d')
                        display_cols = ["date", "time", "category", "amount", "description"]
                        existing_display_cols = [col for col in display_cols if col in df_display.columns]
                        df_display_sorted = df_display.sort_values(by=['date', 'time'], ascending=False)
                        st.dataframe(df_display_sorted[existing_display_cols])
                    else:
                        st.write(f"No expenses found for {month_select}.")
        else:
            st.info("No expenses recorded yet.")

    elif page == "Spending Trends":
        st.header("Spending Trends")
        df_user = get_user_expenses(user_id)
        if not df_user.empty and 'month' in df_user.columns and 'category' in df_user.columns and 'amount' in df_user.columns:
            df_user['month'] = df_user['month'].fillna('').astype(str).str.strip().str.title()
            df_user['category'] = df_user['category'].fillna('other').astype(str).str.strip().str.lower()
            df_user['amount'] = pd.to_numeric(df_user['amount'], errors='coerce').fillna(0.0)
            df_user_trends = df_user[df_user['month'] != ''].copy()
            if not df_user_trends.empty:
                try:
                    df_user_trends['month_dt'] = pd.to_datetime(df_user_trends['month'], format='%B %Y', errors='coerce')
                    df_user_trends = df_user_trends.dropna(subset=['month_dt']).sort_values('month_dt')
                except Exception:
                    df_user_trends = df_user_trends.sort_values('month')
                grouped = df_user_trends.groupby(['month', 'category'])['amount'].sum().unstack(fill_value=0).reset_index()
                if 'month_dt' in df_user_trends.columns:
                    month_order = df_user_trends.drop_duplicates(subset=['month'])\
                                            .sort_values('month_dt')['month'].tolist()
                    grouped['month'] = pd.Categorical(grouped['month'], categories=month_order, ordered=True)
                    grouped = grouped.sort_values('month')
                if len(grouped.columns) > 1:
                    fig = px.bar(grouped, x="month", y=[col for col in grouped.columns if col != 'month'], title="Category-Wise Spending by Month", barmode="stack")
                    st.plotly_chart(fig)
                else:
                    st.info("Not enough data or categories to plot trends.")
            else:
                st.info("No expense data with valid months available for trends.")
        else:
            st.info("No expenses recorded yet or missing required columns (month, category, amount).")

# --- Footer ---
st.markdown("---")
st.caption("Expense Tracker v2.11 - Powered by Supabase & bcrypt")