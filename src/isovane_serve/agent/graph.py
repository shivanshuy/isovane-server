"""Release-gate graph for `langgraph dev`.

The verdict comes from `judge`. A chat model is not on the path.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

from isovane_serve.gate import judge, parse_action


class GateState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    action: dict[str, Any]
    verdict: str
    reason: str


def _latest_user_text(messages: list[BaseMessage]) -> str:
    for message in reversed(messages):
        if isinstance(message, HumanMessage):
            content = message.content
            return content if isinstance(content, str) else json.dumps(content)
    return ""


def parse_node(state: GateState) -> dict[str, Any]:
    return {"action": parse_action(_latest_user_text(list(state.get("messages") or [])))}


def judge_node(state: GateState) -> dict[str, str]:
    return judge(state.get("action"))


def reply_node(state: GateState) -> dict[str, list[AIMessage]]:
    verdict = state.get("verdict") or "deny"
    reason = state.get("reason") or "No decision."
    action = state.get("action") or {}
    tool = action.get("tool") or "unknown"
    return {
        "messages": [
            AIMessage(
                content=f"{verdict.upper()} {tool}. {reason}",
                additional_kwargs={"verdict": verdict, "tool": tool, "reason": reason},
            )
        ]
    }


def build_graph() -> Any:
    builder = StateGraph(GateState)
    builder.add_node("parse", parse_node)
    builder.add_node("judge", judge_node)
    builder.add_node("reply", reply_node)
    builder.add_edge(START, "parse")
    builder.add_edge("parse", "judge")
    builder.add_edge("judge", "reply")
    builder.add_edge("reply", END)
    return builder.compile()


graph = build_graph()
