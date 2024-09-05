"""Module for abstracting tokens from the lexer into intermediate tokens."""

from ply.lex import lex
import components.lexer as token_rules


class Abstractor:
    """Abstractor component class to abstract tokens from the lexer."""

    def __init__(self):

        # File being abstracted
        self.file_name = None

        # Lexer setup
        self.lexer = lex(module=token_rules)  # lexer rules
        self.last_token = None  # Last token seen
        self.peeked_token = None  # Next token to be seen

        # Abstracting variables/operations/functions
        self.var_abstractor = {}  # all variables seen until now and their corresponding abstracted variable name
        self.var_count = 0  # count of variables seen
        self.op_abstractor = {}  # all operations seen until now and their corresponding abstracted operation name
        self.op_count = 0  # count of operations seen
        self.func_abstractor = {}  # all functions seen until now and their corresponding abstracted function name
        self.func_count = 0  # count of functions seen

        # Auxiliary variables for code context
        self.in_parens = 0  # count of parenthesis opened
        self.code_block = []  # code block context (if/else/while/for/foreach/switch/function)
        self.check_if_oneliner = False  # flag to check if code block has no curly braces (one-liner)
        self.rparen_count = 0  # count of right parenthesis we must see before closing parenthesis
        self.in_func_decl = False  # flag to check if we are in a function declaration
        self.in_func_call = False  # flag to check if we are in a function call

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
        """Set the current lex position."""
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
        # Check if it's a condition with one line or not
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
                # Abstract variable names (e.g. $username -> VAR1)
                if t.value in self.var_abstractor:
                    t.type = self.var_abstractor[t.value]
                else:
                    self.var_count += 1
                    self.var_abstractor[t.value] = f"VAR{self.var_count}"
                    t.type = f"VAR{self.var_count}"

            case "OPERATOR":
                # Abstract operators (e.g. == -> OP1)
                if t.value == "=":  # assigment will always be OP0
                    t.type = "OP0"
                elif t.value in self.op_abstractor:
                    t.type = self.op_abstractor[t.value]
                else:
                    self.op_count += 1
                    self.op_abstractor[t.value] = f"OP{self.op_count}"
                    t.type = f"OP{self.op_count}"

            case "IF" | "ELSEIF" | "WHILE" | "FOR" | "FOREACH" | "SWITCH": # simple code blocks have code block type 1
                # oneliner flag and 1 for if/elseif/while/for
                self.code_block.append([False, 1]) # 1 for if/elseif/while/for simple code block
                self.in_parens += 1
                self.__skip_until("LPAREN")

            case "ELSE":
                # oneliner flag and 2 for else
                self.code_block.append([False, 2]) # 2 for else
                self.check_if_oneliner = True

            case "DO":
                # oneliner flag and 3 for do
                self.code_block.append([False, 3]) # 3 for do
                self.check_if_oneliner = True

            case "LPAREN":
                if self.in_parens:
                    self.rparen_count += 1 # rparen goes up to know when we are out of the parenthesis
                if self.last_token and "FUNC_CALL" in self.last_token.type:
                    # if the last token was a function call then we are in a function call and so in parentheses
                    pass

            case "RPAREN":
                # if we are in a parenthesis then we decrease the count and see if we are out of the parenthesis
                if self.in_parens:
                    if self.rparen_count == 0:
                        self.in_parens -= 1
                        t.type = "END_PARENS"
                        # If it's not a do-while or function block then next is a condition
                        if not self.in_func_call:
                            if self.code_block and self.code_block[-1][1] not in [0, 3]:
                                self.check_if_oneliner = True
                        else:
                            self.in_func_call = False
                    else:
                        self.rparen_count -= 1
            case "SEMI":
                # check if we were in a code block that is an oneliner
                if self.code_block and self.code_block[-1][0] is True:
                    # if it was an oneliner then we are out of the code block
                    t.type = "END_CF"
                    if self.code_block[-1][1] == 3:
                        # if it was a do-while then we are in a while block now
                        self.in_parens += 1
                        self.__skip_until("WHILE")
                    self.code_block.pop()

            case "RBRACE":
                # if we were in a code block then we are out of it
                if self.code_block:
                    if self.code_block[-1][1] == 0:
                        # if it was a function block then we are out of the function
                        t.type = "END_FUNC"
                    elif self.code_block[-1][0] is False:
                        # if it was a code block that is not an oneliner then we are out of the code block
                        t.type = "END_CF"
                        if self.code_block[-1][1] == 3:
                            # if it was a do-while then we are in a while block now
                            self.in_parens += 1
                            self.__skip_until("WHILE")
                    self.code_block.pop()

            case "FUNCTION":
                # Now we are in a function declaration
                self.code_block.append([False, 0, ""])
                self.in_func_decl = True

            case "STRING":
                # Abstract function names (e.g. "foo" -> FUNC1)
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
                        self.in_func_call = True
            case "INPUT":
                # Remove unnecessary tokens afert an input token
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
