# expect: LLM-04
def report(client, db, request_text):
    reply = client.messages.create(model="m", max_tokens=200, messages=[{"role": "user", "content": request_text}])
    query = reply.content[0].text
    return db.execute(query).fetchall()
