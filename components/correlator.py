from components.abstractor import Abstractor
from utils.abstract_token import AbsToken


class Correlator:
    """Correlator component class to correlate abstracted tokens."""

    def __init__(self, abstractor: Abstractor):
        self.abstractor = abstractor
        self.data_structure = {}
        self.current_token = None

    def correlate(self, depth, order, flow_type):
        """Correlate the abstracted tokens."""
        while True:  # Iterate over the tokens
            self.current_token = self.__next_token(depth, order, flow_type)
            if not self.current_token or self.current_token.token_type == 'END_CF':
                break  # End of correlation since no more tokens or end of code block

            match self.current_token.token_type:
                ### Handle assignment operations ###
                case "OP1":  # TODO: Must be ' = ' operation not OP1
                    if self.last_token and 'VAR' in self.last_token.token_type:
                        self.__handle_assignment(
                            self.last_token, depth, order, flow_type)

                ### Handle control flows ###
                case "IF" | "WHILE" | "FOR" | "FOREACH" | "SWITCH" | "DO":
                    flow_type = 1
                    self.correlate(depth+1, order, flow_type)
                    order += 1
                case "ELSE":
                    self.correlate(depth+1, order, -1)
                case "ELSEIF":
                    flow_type += 1
                    self.correlate(depth+1, order, flow_type)

                ### Handle possible vulnerabilities ###
                case "INPUT":
                    pass
                # XSS
                case "XSS_SENS":
                    self.__handle_assignment(
                        self.current_token, depth, order, flow_type)
                case "XSS_SANF":
                    pass
                # SQLI
                case "SQLI_SENS":
                    pass
                case "SQLI_SANF":
                    pass

            self.last_token = self.current_token

    def __next_token(self, depth, order, flow_type):
        """Get the next token from the abstractor."""
        t = self.abstractor.token()
        if not t:
            return None
        return AbsToken(t.type, t.lineno, t.lexpos, depth, order, flow_type)

    def __handle_assignment(self, assignee, depth, order, flow_type):
        """Handle assignment operations creating data flow."""
        assignors = self.data_structure.get(assignee, [])
        while self.current_token and self.current_token.token_type not in ('SEMI', 'END_CF'):

            if 'OP' in self.current_token.token_type:
                pass

            elif 'FUNC_CALL' in self.current_token.token_type:  # TODO - Handle function calls
                while self.current_token and self.current_token.token_type != 'END_PARENS':
                    self.current_token = self.__next_token(
                        depth, order, flow_type)
            else:
                assignors.append(self.current_token)

            self.current_token = self.__next_token(depth, order, flow_type)

        self.data_structure[assignee] = assignors
