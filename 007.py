from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()
# api_key = os.getenv("OPENAI_API_KEY")

client = OpenAI()
response = client.responses.create(
    model = "gpt-5.6-terra",
    input = "How to connect to a database with python"
)

print(response.output_text)
