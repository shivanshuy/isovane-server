"""LangGraph workflow without HITL before tools — inventory + agency signals."""

from langgraph.graph import StateGraph, START, END


def intake(state):
    return state


def agent(state):
    return state


def tools(state):
    return state


def route(state):
    return "tools" if state.get("need_tools") else "end"


builder = StateGraph(dict)
builder.add_node("intake", intake)
builder.add_node("agent", agent)
builder.add_node("tools", tools)
builder.add_edge(START, "intake")
builder.add_edge("intake", "agent")
builder.add_conditional_edges(
    "agent",
    route,
    {"tools": "tools", "end": END},
)
builder.add_edge("tools", "agent")
app = builder.compile()
