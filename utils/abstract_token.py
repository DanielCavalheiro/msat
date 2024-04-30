class AbsToken:
    """Abstract token class to represent tokens after abstracting."""

    def __init__(self, token_type, line_num, lexpos, depth, order, flow_type):
        self.token_type = token_type
        self.line_num = line_num
        self.lexer_pos = lexpos
        self.depth = depth
        self.order = order
        self.flow_type = flow_type

    def __str__(self):
        return f"AbsToken({self.token_type}, {self.line_num}, {self.lexer_pos}, {self.depth}, {self.order}, {self.flow_type})"

    def __eq__(self, value: object) -> bool:
        return self.__str__() == value.__str__()

    def __hash__(self) -> int:
        return hash(self.__str__())
