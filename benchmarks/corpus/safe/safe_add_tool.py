# expect: none
from langchain.tools import tool


@tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
