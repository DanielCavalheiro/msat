"""Abstract token class to represent tokens after abstraction and correlation."""

import json
import base64


class AbsToken:
    """Abstract token class to represent tokens after abstraction and correlation."""

    def __init__(self, token_type, line_num, lexpos, depth, order, flow_type):
        self.token_type = token_type
        self.line_num = line_num
        self.token_pos = lexpos
        self.depth = depth
        self.order = order
        self.flow_type = flow_type

    def __str__(self):
        return f"AbsToken({self.token_type}, {self.line_num}, {self.token_pos}, {self.depth}, {self.order}, {self.flow_type})"

    def __eq__(self, value: object) -> bool:
        return self.__str__() == value.__str__()

    def __hash__(self) -> int:
        return hash(self.__str__())


class EncToken(AbsToken):
    """Encrypted token class to represent tokens after encryption."""

    def __str__(self):
        return f"{self.token_type}${self.line_num}${self.token_pos}${self.depth}${self.order}${self.flow_type}"


class EncTokenEncoder(json.JSONEncoder):
    """JSON encoder for EncToken class."""

    def default(self, o):
        if isinstance(o, EncToken):
            return o.__dict__
        elif isinstance(o, bytes):
            return base64.b64encode(o).decode("utf-8")
        return json.JSONEncoder.default(self, o)
