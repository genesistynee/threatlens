from ai.ollama_client import ask_ollama


prompt = """
Explain what a cybersecurity attack timeline is.

Give the answer in exactly two sentences.
"""


print("Sending request to Gemma 3 4B...")

response = ask_ollama(prompt)

print("\n" + "=" * 60)
print("GEMMA RESPONSE")
print("=" * 60)
print(response)