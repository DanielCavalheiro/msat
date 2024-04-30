from components.abstractor import Abstractor
from utils.abstract_token import AbsToken


class Correlator:
    """Correlator component class to correlate abstracted tokens."""

    def __init__(self, abstractor, current_token, last_token, data_structure, depth, order, flow_type):
        self.current_token = current_token
        self.last_token = last_token
        self.abstractor = abstractor
        self.data_structure = data_structure

        # IToken variables
        self.depth = depth
        self.order = order
        self.flow_type = flow_type

    def correlate(self):
        """Correlate the abstracted tokens."""
        while True:  # Iterate over the tokens
            self.current_token = self.__next_token()
            if not self.current_token or self.current_token.token_type == 'END_CF':
                break  # End of correlation since no more tokens or end of code block

            match self.current_token.token_type:
                case "OP1":  # TODO: Must be ' = ' operation not OP1
                    if self.last_token and 'VAR' in self.last_token.token_type:
                        self.__handle_assignment(self.last_token)
                case "IF":
                    pass
                case "ELSE":
                    pass
                case "ELSEIF":
                    pass
                case "WHILE":
                    pass
                case "FOR":
                    pass
                case "FOREACH":
                    pass
                case "SWITCH":
                    pass
                case "DO":
                    pass

            self.last_token = self.current_token

    def __next_token(self):
        """Get the next token from the abstractor."""
        t = self.abstractor.token()
        if not t:
            return None
        return AbsToken(t.type, t.lineno, t.lexpos, self.depth, self.order, self.flow_type)

    def __handle_assignment(self, assignee):
        """Handle assignment operations creating data flow."""
        assignors = self.data_structure.get(assignee, [])
        while self.current_token and self.current_token.token_type != 'SEMI':

            if 'OP' in self.current_token.token_type:
                pass

            elif 'FUNC_CALL' in self.current_token.token_type:  # TODO - Handle function calls
                while self.current_token and self.current_token.token_type != 'END_PARENS':
                    self.current_token = self.__next_token()
            else:
                assignors.append(self.current_token)

            self.current_token = self.__next_token()

        self.data_structure[assignee] = assignors
