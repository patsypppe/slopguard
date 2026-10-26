# expect: LLM-01
def answer(client, request):
    topic = request.args["topic"]
    return client.messages.create(
        model="m",
        max_tokens=300,
        system=f"You are a support bot. Only discuss {topic}.",
        messages=[{"role": "user", "content": "hello"}],
    )
