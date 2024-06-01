"""Module for the Correlator component"""

from components.abstractor import Abstractor
from utils.token_utils import AbsToken


class Correlator:
    """Correlator component class to correlate abstracted tokens."""

    def __init__(self, abstractor: Abstractor, data_structure, depth, flow_type, scope, scope_by_name):
        self.abstractor = abstractor            # Abstractor instance
        self.data_structure = data_structure    # Data structure to store correlations
        self.depth = depth                      # Depth of the current tokens
        self.order = 0                          # Order of the current token
        self.control_flow_counter = 0           # Counter for control flows to keep orders
        self.flow_type = flow_type              # Type of the current flow
        self.current_token = None               # Current token
        self.last_token = None                  # Last token
        self.next_depth_correlator = None       # Next depth correlator
        self.scope = scope                      # Scope of the current tokens
        self.scope_by_name = scope_by_name      # Scope by name of func or file

    def update(self, order, flow_type, current_token, last_token):
        """Update the correlator with new order and flow type."""
        self.order = order
        self.flow_type = flow_type
        self.current_token = current_token
        self.last_token = last_token

    def correlate(self):
        """Correlate the abstracted tokens."""
        elseif_counter = 0

        while True:  # Iterate over the tokens

            if self.last_token and self.last_token.token_type == "END_CF":
                # Leave the current depth if the last token was the end of a control flow
                break

            self.current_token = self.__next_token()  # Next token to correalate

            if not self.current_token:
                break  # End of correlation at current depth

            match self.current_token.token_type:
                # ----------------------- Handle assignment operations ----------------------- #
                case "OP0":  # FIXME: This is a temporary solution is it good?
                    if self.last_token and "VAR" in self.last_token.token_type:
                        self.__handle_correlation(self.last_token)

                # --------------------------- Handle control flows --------------------------- #
                case "IF":
                    self.control_flow_counter += 1
                    elseif_counter = 1  # starts at 1 because of the IF
                    self.__correlate_next_depth(self.control_flow_counter, 1)
                case "ELSE":
                    self.__correlate_next_depth(self.control_flow_counter, -1)
                case "ELSEIF":
                    elseif_counter += 1
                    self.__correlate_next_depth(
                        self.control_flow_counter, elseif_counter)

                case "WHILE" | "FOR" | "FOREACH" | "SWITCH" | "DO":
                    self.control_flow_counter += 1
                    self.__correlate_next_depth(self.control_flow_counter, 1)

                # ----------------------------- Handle functions ----------------------------- #

                case "FUNCTION":
                    self.current_token = self.__next_token()

                case "FUNC_CALL":
                    pass

                # ---------------------- Handle possible vulnerabilities --------------------- #
                case "INPUT":
                    pass
                # XSS
                case "XSS_SENS":
                    self.__handle_correlation(self.current_token)
                case "XSS_SANF":
                    pass  # TODO: mysqli_stmt_bind_param
                # SQLI
                case "SQLI_SENS":
                    self.__handle_sqli_sens()
                case "SQLI_SANF":
                    pass

            self.last_token = self.current_token

    def __next_token(self):
        """Get the next token from the abstractor."""
        t = self.abstractor.token()
        if not t:
            return None
        return AbsToken(t.type, t.lineno, t.lexpos, self.depth, self.order, self.flow_type, self.scope)

    def __correlate_next_depth(self, order: int, flow_type: int):
        if not self.next_depth_correlator:
            self.next_depth_correlator = Correlator(
                self.abstractor, self.data_structure, self.depth + 1, flow_type, self.scope, self.scope_by_name)
        self.next_depth_correlator.update(
            order, flow_type, self.current_token, self.last_token)
        self.next_depth_correlator.correlate()

    def __correlate_function(self):
        """Correlate the function tokens."""
        pass

    def __handle_correlation(self, assignee: AbsToken):
        """Handle assignment operations creating data flow."""
        assignee_name = assignee.token_type
        assignors = self.data_structure.get(assignee_name, [])

        while self.current_token and self.current_token.token_type not in ("SEMI", "END_CF"):

            if "VAR" in self.current_token.token_type or self.current_token.token_type in ("ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT"):
                assignors.append(self.current_token)

            elif ("FUNC_CALL" in self.current_token.token_type):  # TODO - Handle function
                while (self.current_token and self.current_token.token_type != "END_PARENS"):
                    self.current_token = self.__next_token()

            elif self.current_token.token_type == "INPUT":
                assignors.append(self.current_token)
                while (self.current_token and self.current_token.token_type != "RPAREN"):
                    self.current_token = self.__next_token()

            elif "_SANF" in self.current_token.token_type:
                assignors.append(self.current_token)
                while (self.current_token and self.current_token.token_type != "RPAREN"):
                    self.current_token = self.__next_token()

            elif "SQLI_SENS" == self.current_token.token_type:
                assignors.append(self.current_token)
                self.__handle_sqli_sens()

            self.current_token = self.__next_token()

        if assignors:
            self.data_structure[assignee_name] = assignors

    def __handle_sqli_sens(self):
        """Handle SQL Injection sensitive operations."""
        sql_sens = self.data_structure.get("SQLI_SENS", [])

        self.current_token = self.__next_token()
        while self.current_token and self.current_token.token_type != "RPAREN":
            sql_sens.append(self.current_token)
            self.current_token = self.__next_token()

        self.data_structure["SQLI_SENS"] = sql_sens

    def __get_scope(self, token: AbsToken):
        """Get the scope of the current token if exists."""
        pass
