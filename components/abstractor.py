"""Module for abstracting tokens from the lexer into intermediate tokens."""

from ply.lex import lex
import components.lexer as token_rules


class IntermediateToken:
    """Intermediate token class to represent tokens after abstracting."""

    def __init__(self, token_type, line_num, depth, order, flow_type):
        self.token_type = token_type
        self.line_num = line_num
        self.depth = depth
        self.order = order
        self.flow_type = flow_type

    def __str__(self):
        return f"IToken({self.token_type}, {self.line_num}, {self.depth}, {self.order}, {self.flow_type})"


class Abstractor:
    """Abstractor component class to abstract tokens from the lexer."""

    def __init__(self):
        # Lexer setup
        self.lexer = lex(module=token_rules)
        self.last_token = None

        # Abstracting vars
        self.var_abstractor = {}
        self.var_count = 0
        self.op_abstractor = {}
        self.op_count = 0

        # Auxiliary variables
        self.in_condition = False
        self.control_flow = []

    @property
    def lineno(self):
        """Get the current line number."""
        return self.lexer.lineno

    @lineno.setter
    def lineno(self, value):
        self.lexer.lineno = value

    @property
    def lexpos(self):
        """Get the current lex position."""
        return self.lexer.lexpos

    @lexpos.setter
    def lexpos(self, value):
        self.lexer.lexpos = value

    def current_state(self):
        """Get the current state of the lexer."""
        return self.lexer.current_state()

    def input(self, data):
        """Set the input data for the lexer."""
        self.lexer.input(data)

    def next_lexer_token(self):
        """Get the next token from the lexer."""
        return self.lexer.token()

    def token(self):
        """Get the next token from the lexer, abstracted."""
        t = self.next_lexer_token()

        # Will reach this code if the last token was a control flow token
        # Check if its a condition with one line or not
        # and skip over the tokens until the condition ends
        while t and self.in_condition:
            # TODO: There could be an expression with ) in the condition
            if t.type == "RPAREN":
                self.in_condition = False
                t = self.next_lexer_token()
            while t and t.type in token_rules.filtered:
                t = self.next_lexer_token()
            if t and t.type == "LBRACE":
                self.control_flow[-1] = False
                self.in_condition = False
            t = self.next_lexer_token()

        # Filter out tokens that are not needed for analysis.
        while t and t.type in token_rules.filtered:
            # Skip over open tags, but keep track of when we see them.
            if t.type == "OPEN_TAG":
                if self.last_token and self.last_token.type == "SEMI":
                    # Rewrite ?><?php as a semicolon.
                    t.type = "SEMI"
                    t.value = ";"
                    break
                self.last_token = t
                t = self.next_lexer_token()
                continue

            # Rewrite <?= to yield an "echo" statement.
            if t.type == "OPEN_TAG_WITH_ECHO":
                t.type = "ECHO"
                break

            # Insert semicolons in place of close tags where necessary.
            if t.type == "CLOSE_TAG":
                if self.last_token and self.last_token.type in (
                    "OPEN_TAG",
                    "SEMI",
                    "COLON",
                    "LBRACE",
                    "RBRACE",
                ):
                    # Don't insert semicolons after these tokens.
                    pass
                else:
                    # Rewrite close tag as a semicolon.
                    t.type = "SEMI"
                    break

            t = self.next_lexer_token()

        # Reached end of the tokens
        if not t:
            return

        match t.type:
            case "VARIABLE":
                if t.value in self.var_abstractor:
                    t.type = self.var_abstractor[t.value]
                else:
                    self.var_count += 1
                    self.var_abstractor[t.value] = f"VAR{self.var_count}"
                    t.type = f"VAR{self.var_count}"
            case "OPERATOR":
                if t.value in self.op_abstractor:
                    t.type = self.op_abstractor[t.value]
                else:
                    self.op_count += 1
                    self.op_abstractor[t.value] = f"OP{self.op_count}"
                    t.type = f"OP{self.op_count}"
            case "IF" | "ELSE" | "ELSEIF" | "WHILE" | "FOR":  # TODO: Missing "FOREACH" "SWITCH" "DO"
                self.control_flow.append(True)
                self.in_condition = True
            case "SEMI":
                if self.control_flow and self.control_flow[-1] is True:
                    self.control_flow.pop()
                    t.type = "END_CF"
            case "RBRACE":
                if self.control_flow and self.control_flow[-1] is False:
                    self.control_flow.pop()
                    t.type = "END_CF"

        self.last_token = t

        return t

    # Iterator interface
    def __iter__(self):
        return self

    def __next__(self):
        t = self.token()
        if t is None:
            raise StopIteration
        return t

    # __next__ = next
