"""Bake-off: aliased user input must still reach SystemMessage (AST taint)."""

from langchain_core.messages import SystemMessage


def handle(request):
    raw = request.json["prompt"]
    msg = raw  # alias — naive name heuristics miss this
    return SystemMessage(content=f"Instructions. User said: {msg}")


def safe_static():
    # Precision: must NOT be treated as tainted
    return SystemMessage(content="You are a helpful assistant.")
