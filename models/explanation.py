from dataclasses import dataclass, field


@dataclass
class Explanation:

    steps: list[str] = field(default_factory=list)

    def add(self, text):
        self.steps.append(text)