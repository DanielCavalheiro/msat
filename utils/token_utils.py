"""Abstract token class to represent tokens after abstraction and correlation."""

import json


class AbsToken:
    """Abstract token class to represent tokens after abstraction and correlation."""

    def __init__(self, token_type, line_num, lexpos, depth, order, flow_type, split, scope):
        self.token_type = token_type
        self.line_num = line_num
        self.token_pos = lexpos
        self.depth = depth
        self.order = order
        self.flow_type = flow_type
        self.split = split
        self.scope = scope

    def __str__(self):
        return f"AbsToken({self.token_type}, {self.line_num}, {self.token_pos}, {self.depth}, {self.order}, {self.flow_type}, {self.split}, {self.scope})"

    def __eq__(self, value: object) -> bool:
        return self.__str__() == value.__str__()

    def __hash__(self) -> int:
        return hash(self.__str__())


class ScopeChangeToken(AbsToken):
    """Token to represent function call"""

    def __init__(self, token_type, line_num, lexpos, depth, order, flow_type, split, scope, scope_name, arguments):
        super().__init__(token_type, line_num, lexpos,
                         depth, order, flow_type, split, scope)
        self.scope_name = scope_name
        self.arguments = arguments

    def __str__(self):
        return f"ScopeChangeToken({self.token_type}, {self.line_num}, {self.token_pos}, {self.depth}, {self.order}, {self.flow_type}, {self.split}, {self.scope}, {self.scope_name}, {str(self.arguments)})"


class ResultToken:
    def __init__(self, token_type, line_num, lexpos, scope, scope_name=None, arguments=None):
        self.token_type = token_type
        self.line_num = line_num
        self.token_pos = lexpos
        self.scope = scope
        self.scope_name = scope_name
        self.arguments = arguments

    def __str__(self):
        str = f"ResultToken({self.token_type}, {self.line_num}, {
            self.token_pos}, {self.scope}"
        if self.scope_name:
            str += f", {self.scope_name}"
            if self.arguments:
                str += ", arguments:"
                for arg in self.arguments:
                    str += f" {ResultToken(arg.token_type, arg.line_num,
                                           arg.token_pos, arg.scope, arg.scope_name, arg.arguments)}"
        str += ")"
        return str


class TokenEncoder(json.JSONEncoder):
    """JSON encoder for AbsToken and ScopeChangeToken class."""

    def default(self, o):
        if isinstance(o, AbsToken) or isinstance(o, ScopeChangeToken):
            return o.__dict__
        return json.JSONEncoder.default(self, o)


def token_decoder(dct):
    """JSON decoder for EncToken class."""
    if "scope_name" in dct:
        return ScopeChangeToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["depth"], dct["order"],
                                dct["flow_type"], dct["split"], dct["scope"], dct["scope_name"], dct["arguments"])
    if "token_type" in dct:
        return AbsToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["depth"], dct["order"],
                        dct["flow_type"], dct["split"], dct["scope"])
    return dct


class ResultEncoder(json.JSONEncoder):
    """JSON encoder for ResultToken class."""

    def default(self, o):
        if isinstance(o, ResultToken):
            return o.__dict__
        return json.JSONEncoder.default(self, o)


def result_decoder(dct):
    """JSON decoder for EncToken class."""
    if "arguments" in dct:
        return ResultToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["scope"], dct["scope_name"],
                           dct["arguments"])
    elif "scope_name" in dct:
        return ResultToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["scope"], dct["scope_name"])
    else:
        return ResultToken(dct["token_type"], dct["line_num"], dct["token_pos"], dct["scope"])
