from prompt_template import chain
from expense_utils import parse_llm_output, update_excel, load_agent

def main():
    print("💰 Welcome to the Smart Expense Tracker")

    while True:
        mode = input("\nType 'add' to log expense, 'ask' to query, or 'q' to quit: ").lower()

        if mode == 'q':
            print("👋 Goodbye!")
            break

        elif mode == 'add':
            user_input = input("Enter expense: ")
            category = input("Enter category: ")  # New prompt for category
            description = input("Enter description: ")  # New prompt for description
            # Using invoke instead of run
            llm_response = chain.invoke({"query": user_input})
            print("LLM Response:", llm_response)  # Debug print to inspect the response
            parsed_data = parse_llm_output(llm_response)
            # Override or add category and description from user input
            parsed_data['category'] = category
            parsed_data['description'] = description
            update_excel(parsed_data)
            print("✅ Expense saved!\n")

        elif mode == 'ask':
            agent = load_agent()
            if agent:
                question = input("Ask your question: ")
                response = agent.invoke(question)  # Changed to invoke for consistency
                print("🤖 Answer:", response)

        else:
            print("❌ Invalid option. Please type 'add', 'ask', or 'q'.")

if __name__ == "__main__":
    main()