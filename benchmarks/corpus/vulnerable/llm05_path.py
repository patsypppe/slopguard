# expect: LLM-05
def save_note(client, text):
    reply = client.messages.create(model="m", max_tokens=50, messages=[{"role": "user", "content": text}])
    filename = reply.content[0].text
    with open(filename, "w") as handle:
        handle.write(text)
