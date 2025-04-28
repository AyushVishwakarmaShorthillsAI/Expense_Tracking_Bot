from langchain_cohere import ChatCohere
from langchain.prompts import PromptTemplate
from dotenv import load_dotenv
import os

load_dotenv()

# set temp as 0 for accurate outputs
llm = ChatCohere(model="command", temperature=0)

prompt = PromptTemplate(
    input_variables=["query"],
    template="""
    You are a helpful assistant. Your task is to process the following request: {query}. 
    Extract the following details:
    - Date: Identify any date mentioned in the input (e.g., "2025-04-25", "25 April 2025", "yesterday", "today"). If no date is explicitly mentioned, leave it blank for the system to handle.
    - Amount: Extract the monetary amount (e.g., "120", "$120").
    - Category: Identify the category if mentioned (e.g., "clothing"). If not mentioned, use "other".

    Respond with a structured output like:
    Date: [date or blank if not mentioned]
    Amount: [number]
    Category: [category]
    """
)

chain = prompt | llm