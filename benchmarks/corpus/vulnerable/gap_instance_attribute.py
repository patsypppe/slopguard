# expect: LLM-02
class Runner:
    def __init__(self, client):
        self.client = client
        self.code = ""

    def generate(self, task):
        reply = self.client.messages.create(model="m", max_tokens=100, messages=[{"role": "user", "content": task}])
        self.code = reply.content[0].text

    def execute(self):
        exec(self.code)
