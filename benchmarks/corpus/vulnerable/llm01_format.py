# expect: LLM-01
def reply(client, request):
    name = request.args.get("name")
    return client.messages.create(
        model="m",
        max_tokens=100,
        system="You are a helpful assistant for {}.".format(name),
        messages=[{"role": "user", "content": "hi"}],
    )
