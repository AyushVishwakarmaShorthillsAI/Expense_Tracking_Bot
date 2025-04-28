from prompt_template import chain
from expense_utils import parse_llm_output, update_excel, load_agent
import pandas as pd
import re
import time

def main():
    print("💰 Welcome to the Smart Expense Tracker")

    while True:
        mode = input("\nType 'add' to log expense, 'ask' to query, or 'q' to quit or 'summary' for monthly summary and 'trends' for spending trend: ").lower()

        if mode == 'q':
            print("👋 Goodbye!")
            break

        elif mode == 'add':
            user_input = input("Enter expense: ")
            category = input("Enter category: ").strip().lower()
            description = input("Enter description: ")
            llm_response = chain.invoke({"query": user_input})
            print("LLM Response:", llm_response)
            parsed_data = parse_llm_output(llm_response, user_input=user_input)
            parsed_data['category'] = category
            parsed_data['description'] = description
            update_excel(parsed_data)
            print("✅ Expense saved!\n")

        elif mode == 'ask':
            agent = load_agent()
            if agent:
                question = input("Ask your question: ")
                print("🤖 Processing your query, please wait...")
                
                # Fallback for total amount by month
                if any(phrase in question.lower() for phrase in ["total amount", "total spent", "sum"]) and "month" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Month'] = df['Month'].astype(str).str.strip().str.title()
                    month_match = re.search(r"(?:month\s*of\s*([a-zA-Z]+\s+\d{4})|\b([a-zA-Z]+\s+\d{4})\s*(?:month)?)", question.lower())
                    if month_match:
                        month = (month_match.group(1) or month_match.group(2) or "").strip().title()
                        if month:
                            total = df[df['Month'] == month]['Amount'].sum()
                            if total > 0:
                                print(f"🤖 Answer: {total}")
                            else:
                                print("🤖 Answer: No expenses found matching the criteria.")
                        else:
                            print("🤖 Could not extract valid month.")
                    else:
                        print("🤖 Could not parse month from query.")
                
                # Fallback for total amount by category and month
                elif any(phrase in question.lower() for phrase in ["total amount", "total spent", "sum"]) and "category" in question.lower() and "month" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    df['Month'] = df['Month'].astype(str).str.strip().str.title()
                    
                    category_match = re.search(r"category\s*['\"]?([^'\"]+)['\"]?|\b(on|for)\s+(\w+)", question.lower())
                    month_match = re.search(r"(?:month\s*of\s*([a-zA-Z]+\s+\d{4})|\b([a-zA-Z]+\s+\d{4})\s*(?:month)?)", question.lower())
                    
                    print(f"Debug - Category Match: {category_match}, Month Match: {month_match}")
                    
                    if category_match and month_match:
                        category = (category_match.group(1) or category_match.group(3) or "").lower().strip()
                        month = (month_match.group(1) or month_match.group(2) or "").strip().title()
                        if category and month:
                            total = df[(df['Category'] == category) & (df['Month'] == month)]['Amount'].sum()
                            if total > 0:
                                print(f"🤖 Answer: {total}")
                            else:
                                print("🤖 Answer: No expenses found matching the criteria.")
                        else:
                            print("🤖 Could not extract valid category or month.")
                    else:
                        print("🤖 Could not parse category or month from query.")
                
                # Fallback for total amount for multiple categories
                elif any(phrase in question.lower() for phrase in ["total amount", "total spent", "sum"]) and "and" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    category_text = re.search(r"(?:on|for)\s+([\w\s]+?)(?:\s+and\s+([\w\s]+))", question.lower())
                    if category_text:
                        categories = []
                        first_cat = category_text.group(1).strip()
                        second_cat = category_text.group(2).strip() if category_text.group(2) else ""
                        if first_cat:
                            categories.append(first_cat)
                        if second_cat:
                            categories.append(second_cat)
                        if categories:
                            total = df[df['Category'].isin(categories)]['Amount'].sum()
                            if total > 0:
                                print(f"🤖 Answer: {total}")
                            else:
                                print("🤖 Answer: No expenses found matching the criteria.")
                        else:
                            print("🤖 Could not extract valid categories.")
                    else:
                        print("🤖 Could not parse categories from query.")
                
                # Fallback for total amount by single category (e.g., "total amount spent on travel")
                elif any(phrase in question.lower() for phrase in ["total amount", "total spent", "sum"]) and any(word in question.lower() for word in ["on", "for"]) and "month" not in question.lower() and "and" not in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    category_match = re.search(r"(?:on|for)\s+(\w+)", question.lower())
                    if category_match:
                        category = category_match.group(1).strip()
                        if category:
                            total = df[df['Category'] == category]['Amount'].sum()
                            if total > 0:
                                print(f"🤖 Answer: {total}")
                            else:
                                print("🤖 Answer: No expenses found matching the criteria.")
                        else:
                            print("🤖 Could not extract valid category.")
                    else:
                        print("🤖 Could not parse category from query.")
                
                # Fallback for fetching unique categories
                elif any(phrase in question.lower() for phrase in ["fetch", "get"]) and "categories" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    unique_categories = df['Category'].unique()
                    print("🤖 Answer: ", list(unique_categories))
                
                # Fallback for fetching unique months
                elif any(phrase in question.lower() for phrase in ["fetch", "get"]) and "months" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Month'] = df['Month'].astype(str).str.strip().str.title()
                    unique_months = df['Month'].unique()
                    print("🤖 Answer: ", list(unique_months))
                
                # Fallback for record-fetching by month
                elif any(phrase in question.lower() for phrase in ["show", "fetch", "get", "all"]) and "month" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Month'] = df['Month'].astype(str).str.strip().str.title()
                    month_match = re.search(r"(?:month\s*of\s*([a-zA-Z]+\s+\d{4})|\b([a-zA-Z]+\s+\d{4})\s*(?:month)?)", question.lower())
                    if month_match:
                        month = (month_match.group(1) or month_match.group(2) or "").strip().title()
                        if month:
                            result = df[df['Month'] == month]
                            if not result.empty:
                                print("🤖 Answer:\n", result.to_string(index=False))
                            else:
                                print("🤖 Answer: No expenses found matching the criteria.")
                        else:
                            print("🤖 Could not extract valid month.")
                    else:
                        print("🤖 Could not parse month from query.")
                
                # Fallback for average amount by category
                elif any(phrase in question.lower() for phrase in ["average", "avg"]) and "amount" in question.lower() and "category" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    category_match = re.search(r"category\s*['\"]?([^'\"]+)['\"]?|\b(on|for)\s+(\w+)", question.lower())
                    if category_match:
                        category = (category_match.group(1) or category_match.group(3) or "").lower().strip()
                        if category:
                            avg_amount = df[df['Category'] == category]['Amount'].mean()
                            if not pd.isna(avg_amount):
                                print(f"🤖 Answer: {avg_amount:.2f}")
                            else:
                                print("🤖 Answer: No expenses found matching the criteria.")
                        else:
                            print("🤖 Could not extract valid category.")
                    else:
                        print("🤖 Could not parse category from query.")
                
                # Fallback for most expensive expense
                elif any(phrase in question.lower() for phrase in ["show", "fetch", "get"]) and "most expensive" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    if not df.empty:
                        max_expense = df.loc[df['Amount'].idxmax()].to_frame().T
                        print("🤖 Answer:\n", max_expense.to_string(index=False))
                    else:
                        print("🤖 Answer: No expenses found.")
                
                # Fallback for count of expenses per category
                elif any(phrase in question.lower() for phrase in ["how many", "count"]) and "category" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    category_counts = df['Category'].value_counts()
                    if not category_counts.empty:
                        print("🤖 Answer:")
                        for category, count in category_counts.items():
                            print(f"{category}: {count}")
                        print(f"Total: {len(df)}")
                    else:
                        print("🤖 Answer: No expenses found.")
                
                # Fallback for record-fetching with single condition (category)
                elif any(phrase in question.lower() for phrase in ["fetch", "get", "all records", "all rows"]) and "category" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    category_match = re.search(r"category\s*is\s*['\"]?([^'\"]+)['\"]?|\bwhere\s+category\s+is\s+(\w+)|with\s+category\s+(\w+)", question.lower())
                    
                    print(f"Debug - Category Match: {category_match}")
                    
                    if category_match:
                        category = (category_match.group(1) or category_match.group(2) or category_match.group(3) or "").lower().strip()
                        if category:
                            result = df[df['Category'] == category]
                            if not result.empty:
                                print("🤖 Answer:\n", result.to_string(index=False))
                            else:
                                print("🤖 Answer: No expenses found matching the criteria.")
                        else:
                            print("🤖 Could not extract valid category.")
                    else:
                        time.sleep(6)
                        response = agent.invoke({"input": question})
                        if hasattr(response, 'content'):
                            print("🤖 Answer:", response.content.strip())
                        else:
                            print("🤖 Answer:", response)
                
                # Fallback for record-fetching with amount condition
                elif any(phrase in question.lower() for phrase in ["fetch", "get", "all records"]) and "amount" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    amount_match = re.search(
                        r"amount\s*(>|<|=|greater than|less than|equals|more than|over|under)\s*(\d+)", 
                        question.lower()
                    )
                    print(f"Debug - Amount Match: {amount_match}")
                    
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
                            print("🤖 Answer:\n", result.to_string(index=False))
                        else:
                            print("🤖 Answer: No expenses found matching the criteria.")
                    else:
                        time.sleep(6)
                        response = agent.invoke({"input": question})
                        if hasattr(response, 'content'):
                            print("🤖 Answer:", response.content.strip())
                        else:
                            print("🤖 Answer:", response)
                
                else:
                    time.sleep(6)
                    response = agent.invoke({"input": question})
                    if hasattr(response, 'content'):
                        print("🤖 Answer:", response.content.strip())
                    else:
                        print("🤖 Answer:", response)

        elif mode == 'summary':
            month = input("Enter month (e.g., April 2025): ").strip()
            df = pd.read_excel("expenses.xlsx")
            df['Month'] = df['Month'].astype(str).str.strip().str.title()
            summary = df[df['Month'] == month].groupby('Category')['Amount'].sum()
            if not summary.empty:
                print(f"\nSpending Summary for {month}:")
                for category, amount in summary.items():
                    print(f"{category}: {amount}")
                print(f"Total: {summary.sum()}")
            else:
                print(f"No expenses found for {month}.")

        else:
            print("❌ Invalid option. Please type 'add', 'ask', or 'q'.")

if __name__ == "__main__":
    main()