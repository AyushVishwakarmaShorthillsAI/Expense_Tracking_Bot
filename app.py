import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import os
import re
from langchain_experimental.agents import create_pandas_dataframe_agent
from langchain_cohere import ChatCohere
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv
import dateparser

# Load environment variables
load_dotenv()

# Initialize Cohere LLM and prompt template
llm = ChatCohere(model="command", temperature=0)
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

# Utility functions from expense_utils.py
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
        elif any(word.lower() in line.lower() for word in ["category"]):
            category_match = re.search(r'category:\s*(\w+)', line, re.IGNORECASE)
            if category_match:
                data['category'] = category_match.group(1)

    if 'date' not in data and user_input:
        parsed_date = dateparser.parse(
            user_input,
            settings={'PREFER_DAY_OF_MONTH': 'first', 'RETURN_AS_TIMEZONE_AWARE': False}
        )
        if parsed_date:
            data['date'] = parsed_date.strftime("%Y-%m-%d")

    if 'date' not in data:
        data['date'] = datetime.today().strftime("%Y-%m-%d")
    if 'amount' not in data:
        data['amount'] = "0"
    if 'category' not in data:
        data['category'] = "other"

    return data

def clean_date(raw_date):
    parsed = dateparser.parse(raw_date, settings={'PREFER_DAY_OF_MONTH': 'first'})
    return parsed.date() if parsed else datetime.today().date()

def update_excel(data, filename="expenses.xlsx"):
    date = clean_date(data.get("date", "today"))
    time = datetime.now().strftime("%H:%M:%S")
    amount = float(data.get("amount", "0").replace("₹", "").replace(",", "").strip())
    category = data.get("category", "other")
    month = date.strftime("%B %Y")
    description = data.get("description", "")

    new_entry = pd.DataFrame([{
        "Date": date,
        "Time": time,
        "Category": category,
        "Amount": amount,
        "Month": month,
        "Description": description
    }])

    if os.path.exists(filename):
        df = pd.read_excel(filename)
        df = pd.concat([df, new_entry], ignore_index=True)
    else:
        df = new_entry

    df.to_excel(filename, index=False)

def load_agent(filename="expenses.xlsx"):
    if not os.path.exists(filename):
        st.error("No expense data found. Please add expenses first.")
        return None

    df = pd.read_excel(filename)
    df['Date'] = pd.to_datetime(df['Date'], errors='coerce')
    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
    df['Month'] = df['Month'].astype(str).str.strip().str.title()

    custom_prompt = """
    You are a data analyst working with a pandas DataFrame containing expense data. The DataFrame has columns: Date (datetime), Time, Category, Amount, Month, and Description. The Date column is in datetime format (YYYY-MM-DD), the Month column is in title case string format (e.g., 'April 2025'), and the Category column is in lowercase string format (e.g., 'food').

    For queries:
    - If the query asks for a total amount by month (e.g., 'total amount spent in April 2025'), use:
      df[df['Month'] == 'April 2025']['Amount'].sum()
    - If the query asks for a total amount by category and month (e.g., 'total amount spent on technology in April 2025'), use:
      df[(df['Category'] == 'technology') & (df['Month'] == 'April 2025')]['Amount'].sum()
    - If the query asks for all records by month (e.g., 'show all expenses for September 2025'), use:
      df[df['Month'] == 'September 2025'].to_string(index=False)
    - If the query asks for a total amount for multiple categories (e.g., 'total amount spent on clothing and technology'), use:
      df[df['Category'].isin(['clothing', 'technology'])]['Amount'].sum()

    Answer the following question: {input}

    Provide the answer directly as a number (for totals) or the filtered DataFrame as a string (for records). If no data is found, state 'No expenses found matching the criteria.' Use the provided DataFrame (`df`) directly. Ensure all conditions are enclosed in parentheses and use `&` for combining conditions or `|` for OR conditions within `isin`.

    When using the `python_repl_ast` tool, provide a **single-line** expression that evaluates to the final result. Do NOT use multi-line code, variable assignments, or print statements.
    """
    
    agent = create_pandas_dataframe_agent(
        llm,
        df,
        verbose=False,
        allow_dangerous_code=True,
        prefix=custom_prompt
    )
    return agent

# Streamlit app
st.set_page_config(page_title="Expense Tracking Bot", layout="wide")
st.title("💰 Expense Tracking Bot")

# Sidebar navigation
page = st.sidebar.selectbox("Navigate", ["Home", "Add Expense", "Query Expenses", "Monthly Summary", "Spending Trends"])

# Home page
if page == "Home":
    st.header("Dashboard")
    if os.path.exists("expenses.xlsx"):
        df = pd.read_excel("expenses.xlsx")
        total_expenses = df["Amount"].sum()
        st.metric("Total Expenses", f"₹{total_expenses:.2f}")
        
        st.subheader("Recent Expenses")
        st.dataframe(df.tail(5)[["Date", "Category", "Amount", "Description"]])
        
        st.subheader("Category-Wise Spending")
        grouped = df.groupby("Category")["Amount"].sum().reset_index()
        fig = px.pie(grouped, values="Amount", names="Category", title="Spending by Category")
        st.plotly_chart(fig)
    else:
        st.info("No expenses recorded yet. Go to 'Add Expense' to start tracking.")

# Add Expense page
elif page == "Add Expense":
    st.header("Add Expense")
    with st.form("expense_form"):
        user_input = st.text_input("Expense Details (e.g., 'Spent ₹50 on food yesterday')")
        category = st.text_input("Category (e.g., food, travel)")
        description = st.text_area("Description")
        submitted = st.form_submit_button("Add Expense")
        
        if submitted:
            if user_input:
                llm_response = chain.invoke({"query": user_input})
                parsed_data = parse_llm_output(llm_response, user_input=user_input)
                parsed_data['category'] = category.lower().strip() or parsed_data['category']
                parsed_data['description'] = description
                update_excel(parsed_data)
                st.success("Expense saved!")
            else:
                st.error("Please enter expense details.")

# Query Expenses page
elif page == "Query Expenses":
    st.header("Query Expenses")
    query = st.text_input("Ask a question (e.g., 'What is the total amount spent on clothing?')", key="query_input")
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
        agent = load_agent()
        if agent:
            with st.spinner("Processing your query..."):
                df = pd.read_excel("expenses.xlsx")
                df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                df['Month'] = df['Month'].astype(str).str.strip().str.title()
                
                # Handle total amount by month
                if any(phrase in query.lower() for phrase in ["total amount", "total spent", "sum"]) and "month" in query.lower():
                    month_match = re.search(r"(?:month\s*of\s*([a-zA-Z]+\s+\d{4})|\b([a-zA-Z]+\s+\d{4})\s*(?:month)?)", query.lower())
                    if month_match:
                        month = (month_match.group(1) or month_match.group(2)).strip().title()
                        total = df[df['Month'] == month]['Amount'].sum()
                        if total > 0:
                            st.write(f"Total: ₹{total:.2f}")
                        else:
                            st.write("No expenses found.")
                
                # Handle total amount by category and month
                elif any(phrase in query.lower() for phrase in ["total amount", "total spent", "sum"]) and "category" in query.lower() and "month" in query.lower():
                    category_match = re.search(r"category\s*['\"]?([^'\"]+)['\"]?|\b(on|for)\s+(\w+)", query.lower())
                    month_match = re.search(r"(?:month\s*of\s*([a-zA-Z]+\s+\d{4})|\b([a-zA-Z]+\s+\d{4})\s*(?:month)?)", query.lower())
                    if category_match and month_match:
                        category = (category_match.group(1) or category_match.group(3)).lower().strip()
                        month = (month_match.group(1) or month_match.group(2)).strip().title()
                        total = df[(df['Category'] == category) & (df['Month'] == month)]['Amount'].sum()
                        if total > 0:
                            st.write(f"Total: ₹{total:.2f}")
                        else:
                            st.write("No expenses found.")
                
                # Handle total amount for multiple categories
                elif any(phrase in query.lower() for phrase in ["total amount", "total spent", "sum"]) and "and" in query.lower():
                    category_text = re.search(r"(?:on|for)\s+([\w\s]+?)(?:\s+and\s+([\w\s]+))", query.lower())
                    if category_text:
                        categories = [category_text.group(1).strip(), category_text.group(2).strip()]
                        total = df[df['Category'].isin(categories)]['Amount'].sum()
                        if total > 0:
                            st.write(f"Total: ₹{total:.2f}")
                        else:
                            st.write("No expenses found.")
                
                # Handle total amount by single category
                elif any(phrase in query.lower() for phrase in ["total amount", "total spent", "sum"]) and any(word in query.lower() for word in ["on", "for"]):
                    category_match = re.search(r"(?:on|for)\s+(\w+)", query.lower())
                    if category_match:
                        category = category_match.group(1).strip()
                        total = df[df['Category'] == category]['Amount'].sum()
                        if total > 0:
                            st.write(f"Total: ₹{total:.2f}")
                        else:
                            st.write("No expenses found.")
                
                # Handle unique categories
                elif any(phrase in query.lower() for phrase in ["fetch", "get"]) and "categories" in query.lower():
                    unique_categories = df['Category'].unique()
                    st.write("Categories:", ", ".join(unique_categories))
                
                # Handle records by month
                elif any(phrase in query.lower() for phrase in ["show", "fetch", "get", "all"]) and "month" in query.lower():
                    month_match = re.search(r"(?:month\s*of\s*([a-zA-Z]+\s+\d{4})|\b([a-zA-Z]+\s+\d{4})\s*(?:month)?)", query.lower())
                    if month_match:
                        month = (month_match.group(1) or month_match.group(2)).strip().title()
                        result = df[df['Month'] == month]
                        if not result.empty:
                            st.dataframe(result)
                        else:
                            st.write("No expenses found.")
                
                # Handle records by category
                elif any(phrase in query.lower() for phrase in ["fetch", "get", "all records", "all rows"]) and "category" in query.lower():
                    category_match = re.search(r"category\s*is\s*['\"]?([^'\"]+)['\"]?|\bwhere\s+category\s+is\s+(\w+)|with\s+category\s+(\w+)", query.lower())
                    if category_match:
                        category = (category_match.group(1) or category_match.group(2) or category_match.group(3)).lower().strip()
                        result = df[df['Category'] == category]
                        if not result.empty:
                            st.dataframe(result)
                        else:
                            st.write("No expenses found.")
                
                # Handle records by amount
                elif any(phrase in query.lower() for phrase in ["fetch", "get", "all records"]) and "amount" in query.lower():
                    amount_match = re.search(r"amount\s*(>|<|=|greater than|less than|equals|more than|over|under)\s*(\d+)", query.lower())
                    if amount_match:
                        operator = amount_match.group(1).replace("greater than", ">").replace("less than", "<").replace("equals", "=").replace("more than", ">").replace("over", ">").replace("under", "<")
                        value = float(amount_match.group(2))
                        if operator == '>':
                            result = df[df['Amount'] > value]
                        elif operator == '<':
                            result = df[df['Amount'] < value]
                        elif operator == '=':
                            result = df[df['Amount'] == value]
                        if not result.empty:
                            st.dataframe(result)
                        else:
                            st.write("No expenses found.")
                
                # Handle most expensive expense
                elif any(phrase in query.lower() for phrase in ["show", "fetch", "get"]) and "most expensive" in query.lower():
                    if not df.empty:
                        max_expense = df.loc[df['Amount'].idxmax()]
                        st.dataframe(max_expense.to_frame().T)
                    else:
                        st.write("No expenses found.")
                
                # Handle count of expenses per category
                elif any(phrase in query.lower() for phrase in ["how many", "count"]) and "category" in query.lower():
                    category_counts = df['Category'].value_counts()
                    st.write("Expense Count by Category:")
                    for category, count in category_counts.items():
                        st.write(f"{category}: {count}")
                    st.write(f"Total: {len(df)}")
                
                else:
                    response = agent.invoke({"input": query})
                    if hasattr(response, 'content'):
                        st.write("Answer:", response.content.strip())
                    else:
                        st.write("Answer:", response)

# Monthly Summary page
elif page == "Monthly Summary":
    st.header("Monthly Summary")
    month = st.text_input("Enter month (e.g., April 2025)")
    if month:
        if os.path.exists("expenses.xlsx"):
            df = pd.read_excel("expenses.xlsx")
            df['Month'] = df['Month'].astype(str).str.strip().str.title()
            summary = df[df['Month'] == month].groupby('Category')['Amount'].sum()
            if not summary.empty:
                st.write(f"Spending Summary for {month}:")
                for category, amount in summary.items():
                    st.write(f"{category}: ₹{amount:.2f}")
                st.write(f"Total: ₹{summary.sum():.2f}")
            else:
                st.write(f"No expenses found for {month}.")
        else:
            st.info("No expenses recorded yet.")

# Spending Trends page
elif page == "Spending Trends":
    st.header("Spending Trends")
    if os.path.exists("expenses.xlsx"):
        df = pd.read_excel("expenses.xlsx")
        df['Category'] = df['Category'].astype(str).str.strip().str.lower()
        df['Month'] = df['Month'].astype(str).str.strip()
        grouped = df.groupby(['Month', 'Category'])['Amount'].sum().unstack(fill_value=0).reset_index()
        fig = px.bar(grouped, x="Month", y=grouped.columns[1:], title="Category-Wise Spending by Month", barmode="stack")
        st.plotly_chart(fig)
    else:
        st.info("No expenses recorded yet.")