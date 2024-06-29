"""Module for abstracting tokens from the lexer into intermediate tokens."""

from ply.lex import lex
import components.lexer as token_rules


class Abstractor:
    """Abstractor component class to abstract tokens from the lexer."""

    def __init__(self):

        # File being abstracted
        self.file_name = None

        # Lexer setup
        self.lexer = lex(module=token_rules)
        self.last_token = None
        self.peeked_token = None

        # Abstracting variables/operations/functions
        self.var_abstractor = {}
        self.var_count = 0
        self.op_abstractor = {}
        self.op_count = 0
        self.func_abstractor = {}
        self.func_count = 0

        # Auxiliary variables for code context
        self.in_parens = 0
        self.code_block = []
        self.check_if_oneliner = False
        self.rparen_count = 0
        self.in_func_decl = False

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

    def peek(self):
        """Peek at the next token from the lexer."""
        if self.peeked_token is None:
            self.peeked_token = self.__skip_useless()
        return self.peeked_token

    def next_lexer_token(self):
        """Get the next token from the lexer."""
        if self.peeked_token is not None:
            token = self.peeked_token
            self.peeked_token = None
        else:
            token = self.lexer.token()
        return token

    def token(self):
        """Get the next token from the lexer, abstracted."""
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

        # Will reach this code if the last token was a right parenthesis in a condition statement token
        # Check if its a condition with one line or not
        if self.check_if_oneliner:
            if t and t.type != "LBRACE":
                # Set the oneliner flag to True
                self.code_block[-1][0] = True
            else:
                t = self.__skip_useless()
            self.check_if_oneliner = False

        # Reached end of the tokens
        if not t:
            return

        match t.type:
            case "VARIABLE":
                # if self.code_block:
                #     for i in reversed(self.code_block):
                #         if i[1] == 0:
                #             t.value = i[2] + ":" + t.value
                #             break
                if t.value in self.var_abstractor:
                    t.type = self.var_abstractor[t.value]
                else:
                    self.var_count += 1
                    self.var_abstractor[t.value] = f"VAR{self.var_count}"
                    t.type = f"VAR{self.var_count}"

            case "OPERATOR":
                if t.value == "=":
                    t.type = "OP0"
                elif t.value in self.op_abstractor:
                    t.type = self.op_abstractor[t.value]
                else:
                    self.op_count += 1
                    self.op_abstractor[t.value] = f"OP{self.op_count}"
                    t.type = f"OP{self.op_count}"

            case "IF" | "ELSEIF" | "WHILE" | "FOR" | "FOREACH" | "SWITCH":
                # oneliner flag and 1 for if/elseif/while/for
                self.code_block.append([False, 1])
                self.in_parens += 1
                self.__skip_until("LPAREN")

            case "ELSE":
                # oneliner flag and 2 for else
                self.code_block.append([False, 2])
                self.check_if_oneliner = True

            case "DO":
                # oneliner flag and 3 for do
                self.code_block.append([False, 3])
                self.check_if_oneliner = True

            case "LPAREN":
                if self.in_parens:
                    self.rparen_count += 1
                if self.last_token and "FUNC_CALL" in self.last_token.type:
                    pass

            case "RPAREN":
                if self.in_parens:
                    if self.rparen_count == 0:
                        self.in_parens -= 1
                        t.type = "END_PARENS"
                        # If it's not a do-while or function block then next is a condition
                        if self.code_block and self.code_block[-1][1] not in [0, 3]:
                            self.check_if_oneliner = True
                    else:
                        self.rparen_count -= 1
            case "SEMI":
                if self.code_block and self.code_block[-1][0] is True:
                    t.type = "END_CF"
                    if self.code_block[-1][1] == 3:
                        self.in_parens += 1
                        self.__skip_until("WHILE")
                    self.code_block.pop()

            case "RBRACE":
                if self.code_block:
                    if self.code_block[-1][1] == 0:
                        t.type = "END_FUNC"
                    elif self.code_block[-1][0] is False:
                        t.type = "END_CF"
                        if self.code_block[-1][1] == 3:
                            self.in_parens += 1
                            self.__skip_until("WHILE")
                    self.code_block.pop()

            case "FUNCTION":
                self.code_block.append([False, 0, ""])
                self.in_func_decl = True

            case "STRING":  # TODO: What if function call with in function call
                func_id = self.file_name + "/" + self.__get_func_id(t.value)
                if self.in_func_decl:
                    self.code_block[-1][2] = func_id
                    t.type = func_id
                    self.__skip_until("LPAREN")
                    self.in_parens += 1
                    self.in_func_decl = False
                else:
                    next_token = self.peek()
                    if next_token and next_token.type == "LPAREN":
                        t.type = "FUNC_CALL:" + func_id
                        self.peeked_token = None
                        self.in_parens += 1
            case "INPUT":
                next_token = self.peek()
                if next_token and next_token.type == "LBRACKET":
                    self.__skip_until("RBRACKET")

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

    def __skip_useless(self):
        """Skip over tokens that are not needed for analysis."""
        t = self.next_lexer_token()
        while t and t.type in token_rules.filtered:
            t = self.next_lexer_token()
        return t

    def __skip_until(self, token_type):
        """Skip tokens until a token of the given type is found."""
        t = self.next_lexer_token()
        while t and t.type != token_type:
            t = self.next_lexer_token()
        return t

    def __get_func_id(self, func_name):
        """Get the function id for the given function name."""
        if func_name in self.func_abstractor:
            return self.func_abstractor[func_name]
        else:
            self.func_count += 1
            self.func_abstractor[func_name] = f"FUNC{self.func_count}"
            return f"FUNC{self.func_count}"
