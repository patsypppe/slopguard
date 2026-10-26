# expect: LLM-08
from langchain_experimental.agents import create_pandas_dataframe_agent


def build(llm, frame):
    return create_pandas_dataframe_agent(llm, frame, allow_dangerous_code=True)
