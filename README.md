# Expense Tracking Bot

This is a Streamlit web application for tracking personal expenses on the go, powered by Supabase as the database backend and utilizing Vanna AI for natural language querying.

## Features:

*   **User Authentication:** Secure login and registration.
*   **Add Expenses:** Easily add new expense records with details like date, amount, category, and description.
*   **Query Expenses:** Use natural language to ask questions about your spending (e.g., "How much did I spend on food last month?").
*   **Monthly Summary:** View a breakdown of spending by category for a selected month.
*   **Spending Trends:** Visualize spending patterns over time.

## Setup and Installation

1.  **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd project-1-langchain-Expense-Tracking-bot
    ```

2.  **Install dependencies:**

    Ensure you have Python installed. Install the required libraries using pip. Make sure you have a `requirements.txt` file with all necessary libraries, including `streamlit`, `pandas`, `plotly`, `langchain`, `python-dotenv`, `dateparser`, `streamlit-authenticator`, `PyYAML`, `supabase`, `bcrypt`, `sqlalchemy`, `psycopg2-binary` (or `psycopg2`), `vanna`, and `sentence-transformers`.

    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up Supabase:**

    *   Create a new project on [Supabase](https://supabase.com/).
    *   Set up your database schema, including the `expense` and `users` tables with appropriate columns and relationships as used in `app.py`. You'll also need Row Level Security (RLS) policies enabled and configured for the `expense` table to ensure users can only access their own data (based on `user_id`).
    *   Obtain your Supabase URL, Anon Key, Database Host, Port, Database Name, User, and Password.

4.  **Configure Credentials (Streamlit Secrets):**

    Create a `.streamlit` directory in the root of your project if it doesn't exist. Inside `.streamlit`, create a `secrets.toml` file.

    Add the following credentials, replacing the placeholder values with your actual details:

    ```toml
    [supabase]
    url = "YOUR_SUPABASE_URL"
    key = "YOUR_SUPABASE_ANON_KEY"
    user = "YOUR_SUPABASE_DB_USER" # e.g., postgres or postgres.<project_ref>
    db_host = "YOUR_SUPABASE_DATABASE_HOST" # e.g., db.xxxxxxxxxxxxxxxx.supabase.co or aws-0-<region>.pooler.supabase.com
    db_port = "YOUR_SUPABASE_DATABASE_PORT" # e.g., 5432 for Direct Connection, 6543 for Pooler
    db_password = "YOUR_SUPABASE_DATABASE_PASSWORD"
    database = "YOUR_SUPABASE_DATABASE_NAME" # e.g., postgres

    [auth]
    authenticator_key = "A_RANDOM_SECRET_KEY_FOR_AUTHENTICATOR"

    [vanna]
    api_key = "YOUR_VANNA_API_KEY"
    email = "YOUR_VANNA_EMAIL"
    ```

    *   `YOUR_SUPABASE_URL`: Found in your Supabase Project Settings -> API.
    *   `YOUR_SUPABASE_ANON_KEY`: Found in your Supabase Project Settings -> API.
    *   `YOUR_SUPABASE_DB_USER`: The username for your database connection. For the connection pooler, this is typically `postgres.<project_ref>`.
    *   `YOUR_SUPABASE_DATABASE_HOST`: Found in your Supabase Project Settings -> Database -> Connection info (Direct Connection or Pooler). Use the Pooler host if you intend to use the pooler.
    *   `YOUR_SUPABASE_DATABASE_PORT`: Found in your Supabase Project Settings -> Database -> Connection info (5432 for Direct, 6543 for Pooler). Match this with the host.
    *   `YOUR_SUPABASE_DATABASE_PASSWORD`: The password you set for the `postgres` user.
    *   `YOUR_SUPABASE_DATABASE_NAME`: The name of your database, usually `postgres`.
    *   `authenticator_key`: A random string used by Streamlit Authenticator for cookie signing. Generate a strong, random string.

5.  **Configure Vanna AI (Vanna Cloud):**

    The project is configured to use [Vanna Cloud](https://vanna.ai/). You will need a Vanna Cloud API key and the associated email address.

    *   `YOUR_VANNA_API_KEY`: Your Vanna Cloud API key, obtained from the Vanna Cloud dashboard.
    *   `YOUR_VANNA_EMAIL`: The email address associated with your Vanna Cloud account.

    Configure these in the `[vanna]` section of your `.streamlit/secrets.toml` file as shown in the example above.

## Running the App

To run the Streamlit application, navigate to the project directory in your terminal and execute:

```bash
streamlit run app.py
```

The app should open in your web browser.