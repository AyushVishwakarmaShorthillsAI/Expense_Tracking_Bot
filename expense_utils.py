import pandas as pd
import os
import dateparser
from datetime import datetime
from langchain_experimental.agents import create_pandas_dataframe_agent
from prompt_template import llm
import re

def parse_llm_output(output):
    # Extract the content from AIMessage object
    if hasattr(output, 'content'):
        output = output.content  # Get the actual text content from AIMessage
    
    data = {}
    lines = output.strip().split('\n')
    
    for line in lines:
        if ':' in line:
            key, val = line.split(':', 1)
            data[key.strip().lower()] = val.strip()
        # Fallback: Extract amount if not in key-value format
        elif any(word.lower() in line.lower() for word in ["amount", "cost", "price"]):
            amount_match = re.search(r'[-+]?\d*\.?\d+', line)
            if amount_match:
                data['amount'] = amount_match.group(0)
        # Fallback: Extract date
        elif any(word.lower() in line.lower() for word in ["date"]):
            date_match = re.search(r'\d{4}-\d{2}-\d{2}', line)
            if date_match:
                data['date'] = date_match.group(0)
        # Fallback: Extract category
        elif any(word.lower() in line.lower() for word in ["category"]):
            category_match = re.search(r'category:\s*(\w+)', line, re.IGNORECASE)
            if category_match:
                data['category'] = category_match.group(1)

    # Set defaults if not found
    if 'date' not in data:
        data['date'] = datetime.today().strftime("%Y-%m-%d")
    if 'amount' not in data:
        data['amount'] = "0"
    if 'category' not in data:
        data['category'] = "other"

    return data

def clean_date(raw_date):
    parsed = dateparser.parse(raw_date)
    return parsed.date() if parsed else datetime.today().date()

def update_excel(data, filename="expenses.xlsx"):
    date = clean_date(data.get("date", "today"))
    time = datetime.now().strftime("%H:%M:%S")  # Add current time
    amount = float(data.get("amount", "0").replace("₹", "").strip())
    category = data.get("category", "other")
    month = date.strftime("%B %Y")
    description = data.get("description", "")  # Default to empty string if not provided

    new_entry = pd.DataFrame([{
        "Date": date,
        "Time": time,  # New column for time
        "Category": category,
        "Amount": amount,
        "Month": month,
        "Description": description  # New column for description
    }])

    if os.path.exists(filename):
        df = pd.read_excel(filename)
        # Ensure new columns are added to existing DataFrame
        df = pd.concat([df, new_entry], ignore_index=True)
    else:
        df = new_entry

    df.to_excel(filename, index=False)

def load_agent(filename="expenses.xlsx"):
    if not os.path.exists(filename):
        print("No expense data found.")
        return None

    df = pd.read_excel(filename)
    agent = create_pandas_dataframe_agent(llm, df, verbose=False)
    return agent