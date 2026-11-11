"""Bake-off fixture: intentional agent risks for recall scoring."""

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage


def build(user_text: str):
    # LLM01: user into system prompt
    sys = SystemMessage(content=f"You are helpful. User said: {user_text}")
    model = ChatOpenAI(model="gpt-4o")  # missing max_tokens
    # ASI05: shell=True
    import subprocess

    subprocess.run("echo hi", shell=True)
    return model.invoke([sys, HumanMessage(content=user_text)])
