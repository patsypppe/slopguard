# expect: none
import json


def classify(client, text):
    reply = client.messages.create(model="m", max_tokens=50, messages=[{"role": "user", "content": text}])
    data = json.loads(reply.content[0].text)
    return data.get("label", "unknown")
