from langchain_cohere import ChatCohere
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Initialize the Cohere LLM
llm = ChatCohere(model="command", temperature=0.7)

# Define the prompt with 'query' as the expected variable
prompt = PromptTemplate(
    input_variables=["query"], 
    template="You are a helpful assistant. Your task is to process the following request: {query}. Respond with a structured output like: Date: [date]\nAmount: [amount]\nCategory: [category]"
)

# Use the prompt with the Cohere LLM
chain = prompt | llm