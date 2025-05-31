from vanna.remote import VannaDefault
from vanna.base import VannaBase
from sqlalchemy import create_engine
import urllib.parse
import streamlit as st

def initialize_vanna(user_id: str) -> VannaBase:
    """Initialize Vanna AI with Supabase connection without training."""
    try:
        # Retrieve Supabase credentials from Streamlit secrets
        db_host_raw = st.secrets.get("supabase", {}).get("db_host")
        db_password_raw = st.secrets.get("supabase", {}).get("db_password")
        db_port = 6543  # Supabase default port
        db_name = "postgres"
        db_user = "postgres.xupvavqdvunalnpxqlxa"

        if not db_host_raw or not db_password_raw:
            st.error("Database host or password not found in secrets.")
            return None

        # Retrieve Vanna AI API key and associated email
        vanna_secrets = st.secrets.get("vanna", {})
        api_key = vanna_secrets.get("api_key")
        email = vanna_secrets.get("email")

        if not api_key or not email:
            st.error("Vanna AI API key or email not found in secrets.")
            return None

        # Encode credentials for connection string
        encoded_password = urllib.parse.quote_plus(db_password_raw)
        encoded_db_host = urllib.parse.quote_plus(db_host_raw)
        connection_string = f"postgresql://{db_user}:{encoded_password}@{encoded_db_host}:{db_port}/{db_name}"

        # Create SQLAlchemy engine
        engine = create_engine(connection_string)

        # Initialize Vanna AI with PostgreSQL and API key
        vn = VannaDefault(
            model="command",
            api_key=api_key,
            config={'email': email}
        )

        # Connect to the database
        vn.connect_to_postgres(
            host=encoded_db_host,
            dbname=db_name,
            user=db_user,
            password=db_password_raw,
            port=db_port
        )

        print(f"Vanna AI initialized for user_id: {user_id}")
        return vn

    except Exception as e:
        st.error(f"Failed to initialize Vanna AI: {e}")
        print(f"Exception in initialize_vanna: {e}")
        return None