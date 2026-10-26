# expect: INC-04
def load(path):
    try:
        return open(path).read()
    except Exception:
        pass
