"""Abstract token class to represent tokens after abstraction and correlation."""


class AbsToken:
    """Abstract token class to represent tokens after abstraction and correlation."""

    def __init__(self, token_type, lexpos, depth, order, flow_type):
        self.token_type = token_type
        self.token_pos = lexpos
        self.depth = depth
        self.order = order
        self.flow_type = flow_type

    def __str__(self):
        return f"AbsToken({self.token_type}, {self.token_pos}, {self.depth}, {self.order}, {self.flow_type})"

    def __eq__(self, value: object) -> bool:
        return self.__str__() == value.__str__()

    def __hash__(self) -> int:
        return hash(self.__str__())


class EncToken(AbsToken):
    """Encrypted token class to represent tokens after encryption."""

    def __str__(self):
        return f"{self.token_type}${self.token_pos}${self.depth}${self.order}${self.flow_type}"
