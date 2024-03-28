import components.lexer as token_rules
import ply.lex as lex


class IntermediateToken:
    def __init__(self, token_type, line_num, depth, order, flow_type):
        self.token_type = token_type
        self.line_num = line_num
        self.depth = depth
        self.order = order
        self.flow_type = flow_type

    def __str__(self):
        return f'IToken({self.token_type}, {self.line_num}, {self.depth}, {self.order}, {self.flow_type})'


# Abstractor class
class Abstractor:

    def __init__(self):
        # Lexer setup
        self.lexer = lex.lex(module=token_rules)
        self.last_token = None

        # Additional ITL attributes
        self.depth = 0
        self.order = 0
        self.flow_type = 0

        # Abstracting vars
        self.var_abstractor = {}
        self.var_count = 0
        self.op_abstractor = {}
        self.op_count = 0

    @property
    def lineno(self):
        return self.lexer.lineno

    @lineno.setter
    def lineno(self, value):
        self.lexer.lineno = value

    @property
    def lexpos(self):
        return self.lexer.lexpos

    @lexpos.setter
    def lexpos(self, value):
        self.lexer.lexpos = value

    def current_state(self):
        return self.lexer.current_state()

    def input(self, data):
        self.lexer.input(data)

    def next_lexer_token(self):
        return self.lexer.token()

    def token(self):
        t = self.next_lexer_token()

        # Filter out tokens that are not needed fpr analysis.
        while t and t.type in token_rules.filtered:

            # Skip over open tags, but keep track of when we see them.
            if t.type == 'OPEN_TAG':
                if self.last_token and self.last_token.type == 'SEMI':
                    # Rewrite ?><?php as a semicolon.
                    t.type = 'SEMI'
                    t.value = ';'
                    break
                self.last_token = t
                t = self.next_lexer_token()
                continue

            # Rewrite <?= to yield an "echo" statement.
            if t.type == 'OPEN_TAG_WITH_ECHO':
                t.type = 'ECHO'
                break

            # Insert semicolons in place of close tags where necessary.
            if t.type == 'CLOSE_TAG':
                if self.last_token and \
                        self.last_token.type in ('OPEN_TAG', 'SEMI', 'COLON',
                                                 'LBRACE', 'RBRACE'):
                    # Don't insert semicolons after these tokens.
                    pass
                else:
                    # Rewrite close tag as a semicolon.
                    t.type = 'SEMI'
                    break

            t = self.next_lexer_token()

        # Reached end of the tokens
        if not t:
            return

        match t.type:
            case 'VARIABLE':
                if t.value in self.var_abstractor:
                    t.type = self.var_abstractor[t.value]
                else:
                    self.var_count += 1
                    self.var_abstractor[t.value] = f'VAR{self.var_count}'
                    t.type = f'VAR{self.var_count}'
            case 'OPERATOR':
                if t.value in self.op_abstractor:
                    t.type = self.op_abstractor[t.value]
                else:
                    self.op_count += 1
                    self.op_abstractor[t.value] = f'OP{self.op_count}'
                    t.type = f'OP{self.op_count}'

        self.last_token = t

        return IntermediateToken(t.type, t.lineno, self.depth, self.order, self.flow_type)

    # Iterator interface
    def __iter__(self):
        return self

    def __next__(self):
        t = self.token()
        if t is None:
            raise StopIteration
        return t

    __next__ = next
