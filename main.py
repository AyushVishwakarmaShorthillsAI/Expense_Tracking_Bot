from prompt_template import chain
from expense_utils import parse_llm_output, update_excel, load_agent
import pandas as pd
import re


def main():
    print("💰 Welcome to the Smart Expense Tracker")

    while True:
        mode = input("\nType 'add' to log expense, 'ask' to query, or 'q' to quit or 'summary' for monthly summary and 'trends' for spending trend. : ").lower()

        if mode == 'q':
            print("👋 Goodbye!")
            break

        elif mode == 'add':
            user_input = input("Enter expense: ")
            category = input("Enter category: ")
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
                
                # Special case for total amount queries
                if "total amount spent on category" in question.lower() and "month of" in question.lower():
                    df = pd.read_excel("expenses.xlsx")
                    df['Category'] = df['Category'].astype(str).str.strip().str.lower()
                    df['Month'] = df['Month'].astype(str).str.strip()
                    
                    # Extract category and month using regex
                    category_match = re.search(r"category\s+'([^']+)'\s+", question.lower())
                    month_match = re.search(r"month of\s+([a-zA-Z]+\s+\d{4})", question.lower())
                    
                    if category_match and month_match:
                        category = category_match.group(1).lower()
                        month = month_match.group(1)
                        total = df[(df['Category'] == category) & (df['Month'] == month)]['Amount'].sum()
                        print(f"🤖 Answer: {total}")
                    else:
                        print("🤖 Could not parse category or month from query.")
                else:
                    response = agent.invoke(question)
                    print("🤖 Answer:", response)

        elif mode == 'summary':
            month = input("Enter month (e.g., April 2025): ").strip()
            df = pd.read_excel("expenses.xlsx")
            df['Month'] = df['Month'].astype(str).str.strip()
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