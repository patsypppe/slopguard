# expect: LLM-02
def ask(client, question):
    reply = client.messages.create(model="m", max_tokens=50, messages=[{"role": "user", "content": question}])
    return reply.content[0].text


def solve(client, question):
    return eval(ask(client, question))
