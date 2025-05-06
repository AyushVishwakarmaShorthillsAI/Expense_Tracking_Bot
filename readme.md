# Expense Tracking Bot

A Streamlit application for tracking personal expenses using natural language input, Cohere, and Supabase.

## Quick Start

1.  **Clone & Install:**
    ```bash
    git clone <your-repo-url>
    cd <repo-directory>
    python -m venv .venv
    source .venv/bin/activate # Or .venv\Scripts\activate on Windows
    pip install -r requirements.txt
    ```

2.  **Cohere API Key:**
    *   Create a `.env` file in the root directory.
    *   Add `COHERE_API_KEY="your-key-here"` to the `.env` file.

3.  **Supabase Secrets:**
    *   Create `.streamlit/secrets.toml`.
    *   Add your Supabase credentials (find details in Supabase dashboard -> Project Settings -> API & Database):
        ```toml
        [supabase]
        url = "YOUR_SUPABASE_CLIENT_URL"
        key = "YOUR_SUPABASE_ANON_KEY"
        db_host = "YOUR_SUPABASE_DB_HOST"
        db_port = "YOUR_SUPABASE_DB_PORT"
        db_password = "YOUR_SUPABASE_DATABASE_PASSWORD"

        [auth]
        # Generate with: python -c 'import secrets; print(secrets.token_hex(32))'
        authenticator_key = "YOUR_STRONG_RANDOM_SECRET_KEY"
        ```
    *   Add `.env` and `.streamlit/secrets.toml` to your `.gitignore`.

4.  **Supabase Setup:**
    *   Ensure you have `users` and `expense` tables created in your Supabase project.
    *   **Crucially:** Set up appropriate Row Level Security (RLS) policies for both tables.

5.  **Run Locally:**
    ```bash
    streamlit run app.py
    ```

6.  **Deploy (Streamlit Cloud):**
    *   Push code to GitHub (excluding secrets/env files).
    *   Connect repo to Streamlit Cloud.
    *   Copy the contents of local `.streamlit/secrets.toml` into Streamlit Cloud App Secrets.
    *   Add `COHERE_API_KEY` as a separate secret in Streamlit Cloud.
