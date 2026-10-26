# expect: none
def find(client, db, text):
    reply = client.messages.create(model="m", max_tokens=20, messages=[{"role": "user", "content": text}])
    name = reply.content[0].text
    return db.execute("SELECT * FROM people WHERE name = ?", (name,)).fetchall()
