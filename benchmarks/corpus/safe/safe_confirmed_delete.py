# expect: none
from langchain.tools import tool


@tool
def archive_note(note_id: int, confirmed: bool) -> str:
    """Archive a note after the user confirms."""
    if not confirmed:
        return "needs confirmation"
    return f"archived {note_id}"
