"""Abstract token class to represent tokens after abstraction and correlation."""

import json


class AbsToken:
    """Abstract token class to represent tokens after abstraction and correlation."""

    def __init__(self, token_type, line_num, lexpos, depth, order, flow_type, scope):
        self.token_type = token_type
        self.line_num = line_num
        self.token_pos = lexpos
        self.depth = depth
        self.order = order
        self.flow_type = flow_type
        self.scope = scope

    def __str__(self):
        return f"AbsToken({self.token_type}, {self.line_num}, {self.token_pos}, {self.depth}, {self.order}, {self.flow_type}, {self.scope})"

    def __eq__(self, value: object) -> bool:
        return self.__str__() == value.__str__()

    def __hash__(self) -> int:
        return hash(self.__str__())


class FuncCallToken(AbsToken):
    """Token to represent function call"""

    def __init__(self, token_type, line_num, lexpos, depth, order, flow_type, scope, func_name, arguments):
        super().__init__(token_type, line_num, lexpos, depth, order, flow_type, scope)
        self.func_name = func_name
        self.arguments = arguments

    def __str__(self):
        return f"FuncCallToken({self.token_type}, {self.line_num}, {self.token_pos}, {self.depth}, {self.order}, {self.flow_type}, {self.scope}, {self.func_name}, {str(self.arguments)})"


class TokenEncoder(json.JSONEncoder):
    """JSON encoder for EncToken class."""

    def default(self, o):
        if isinstance(o, AbsToken) or isinstance(o, FuncCallToken):
            return o.__dict__
        return json.JSONEncoder.default(self, o)


def token_decoder(dct):
    """JSON decoder for EncToken class."""
    if "func_name" in dct:
        return FuncCallToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["depth"], dct["order"], dct["flow_type"], dct["scope"], dct["func_name"], dct["arguments"])
    if "token_type" in dct:
        return AbsToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["depth"], dct["order"], dct["flow_type"], dct["scope"])
    return dct
