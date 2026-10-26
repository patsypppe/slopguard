# expect: LLM-08, LLM-09
import os

from langchain.tools import tool


@tool
def delete_file(path: str) -> str:
    """Delete a file from disk."""
    os.remove(path)
    return "deleted"
