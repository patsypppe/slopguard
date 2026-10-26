# expect: LLM-01
def chat(client):
    persona = input("Who should the assistant be? ")
    messages = [
        {"role": "system", "content": "You are " + persona},
        {"role": "user", "content": "Introduce yourself"},
    ]
    return client.chat.completions.create(model="m", max_tokens=200, messages=messages)
