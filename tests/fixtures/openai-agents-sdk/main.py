from __future__ import annotations
from agents import (
    Agent,
    Runner,
    function_tool,
)
from pydantic import BaseModel


class Ctx(BaseModel):
    user_id: str


@function_tool
def lookup(query: str) -> str:
    """Look something up."""
    return "result"


triage_agent = Agent[Ctx](
    name="Triage Agent",
    instructions="Route the user to the right specialist.",
    tools=[lookup],
)
