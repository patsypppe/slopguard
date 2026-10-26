# expect: LLM-06
import requests


def fetch_source(client, topic):
    reply = client.messages.create(model="m", max_tokens=50, messages=[{"role": "user", "content": topic}])
    url = reply.content[0].text
    return requests.get(url, timeout=5).text
