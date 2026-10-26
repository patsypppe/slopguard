# expect: LLM-12
def summarise(client, text):
    return client.chat.completions.create(
        model="m", messages=[{"role": "user", "content": "Summarise: " + text}]
    )
