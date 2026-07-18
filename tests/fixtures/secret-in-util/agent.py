from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI

@tool
def greet(name: str) -> str:
    """Greet someone."""
    return f"hello {name}"

llm = ChatOpenAI(model="gpt-4o")
agent = create_react_agent(llm, [greet], None)
executor = AgentExecutor(agent=agent, tools=[greet])
