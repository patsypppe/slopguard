# expect: none
import json
import os
import pathlib
import sys


def where():
    return pathlib.Path(os.getcwd()) / json.dumps(sys.argv)
