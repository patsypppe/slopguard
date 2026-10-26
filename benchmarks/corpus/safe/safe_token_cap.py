# expect: none
def summarise(client, text):
    return client.chat.completions.create(
        model="m", max_tokens=200, messages=[{"role": "user", "content": text}]
    )
