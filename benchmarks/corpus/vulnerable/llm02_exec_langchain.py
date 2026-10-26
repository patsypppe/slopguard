# expect: LLM-02
def run_generated(llm, task):
    result = llm.invoke(f"Write python code to {task}")
    exec(result.content)
