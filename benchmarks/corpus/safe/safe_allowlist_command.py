# expect: none
import subprocess

ALLOWED = {"status": ["git", "status"], "log": ["git", "log", "-1"]}


def run(client, text):
    reply = client.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": text}])
    choice = reply.content[0].text.strip()
    if choice not in ALLOWED:
        return None
    return subprocess.run(ALLOWED[choice], capture_output=True, text=True).stdout
