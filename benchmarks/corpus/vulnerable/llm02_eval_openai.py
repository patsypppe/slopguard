# expect: LLM-02
def calculate(client, question):
    reply = client.chat.completions.create(
        model="m", max_tokens=100, messages=[{"role": "user", "content": question}]
    )
    expression = reply.choices[0].message.content
    return eval(expression)
