# expect: LLM-03
import subprocess


def helper(client, goal):
    msg = client.messages.create(model="m", max_tokens=100, messages=[{"role": "user", "content": goal}])
    command = msg.content[0].text.strip()
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
