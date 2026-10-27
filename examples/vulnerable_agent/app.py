"""An intentionally vulnerable demo for `slopguard scan examples/vulnerable_agent`.

Every problem here is something an AI assistant can plausibly produce. Never deploy this file.
The repository's own scan skips `examples/`.
"""

import subprocess

from flask import request
from langchain.tools import tool


@tool
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


def answer(client):
    topic = request.args["topic"]
    reply = client.messages.create(
        model="your-model-id",
        max_tokens=300,
        system=f"You are a support bot. Only discuss {topic}.",
        messages=[{"role": "user", "content": "hello"}],
    )
    return eval(reply.content[0].text)


def parse_invoice(path):
    pass


API_TOKEN = "q9X$kP2mZr7LwT4bNc8Vd"
