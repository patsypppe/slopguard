# expect: none
import ast


def parse_list(client, text):
    reply = client.messages.create(model="m", max_tokens=50, messages=[{"role": "user", "content": text}])
    return ast.literal_eval(reply.content[0].text)
