"""Abstract token class to represent tokens after abstraction and correlation."""

import json
import utils.crypto_stuff as crypto_stuff


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
        if isinstance(o, EncToken) or isinstance(o, AbsToken):  # TODO: remove or
            return o.__dict__
        return json.JSONEncoder.default(self, o)


def enc_token_decoder(dct):
    """JSON decoder for EncToken class."""
    if "token_type" in dct:
        return EncToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["depth"], dct["order"], dct["flow_type"])
    return dct
