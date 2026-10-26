# expect: none
from abc import ABC, abstractmethod


class Parser(ABC):
    @abstractmethod
    def parse(self, text):
        pass

    def run(self, text):
        return self.parse(text)
