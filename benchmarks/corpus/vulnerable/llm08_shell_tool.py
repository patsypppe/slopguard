# expect: LLM-08
import subprocess

from langchain.tools import tool


@tool
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
