import pandas as pd
import os
import dateparser
from datetime import datetime
from langchain_experimental.agents import create_pandas_dataframe_agent
from prompt_template import llm
import re

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
    amount = float(data.get("amount", "0").replace("$", "").replace(",", "").strip())
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
        print("No expense data found.")
        return None

    df = pd.read_excel(filename)
    df['Date'] = pd.to_datetime(df['Date'], errors='coerce')
    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
    df['Month'] = df['Month'].astype(str).str.strip()
    print("Loaded DataFrame:\n", df)

    custom_prompt = """
    You are a data analyst working with a pandas DataFrame containing expense data. The DataFrame has columns: Date (datetime), Time, Category, Amount, Month, and Description. The Date column is in datetime format (YYYY-MM-DD), and the Month column is in string format (e.g., 'April 2025'). The Category column is in lowercase string format.

    For queries involving categories and months, filter the DataFrame using string comparisons with the `&` operator for multiple conditions. For example:
    - To find the total amount spent on category 'technology' in April 2025, use:
      total = df[(df['Category'] == 'technology') & (df['Month'] == 'April 2025')]['Amount'].sum()
      print(total)

    Answer the following question: {input}

    Provide the answer as a single number (the total amount) or a clear statement if no data is found (e.g., 'No expenses found for category technology in April 2025'). Do not read from files, generate sample DataFrames, or overcomplicate the logic. Use the provided DataFrame (`df`) directly. Ensure all conditions are enclosed in parentheses and use `&` for combining conditions.
    """

    agent = create_pandas_dataframe_agent(
        llm,
        df,
        verbose=True,
        allow_dangerous_code=True,
        prefix=custom_prompt
    )
    return agent