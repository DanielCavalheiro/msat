"""Module for the Correlator component"""

from components.abstractor import Abstractor
from utils.token_utils import AbsToken


class Correlator:
    """Correlator component class to correlate abstracted tokens."""

    def __init__(self, abstractor: Abstractor, data_structure, depth, flow_type):
        self.abstractor = abstractor
        self.data_structure = data_structure
        self.depth = depth
        self.order = 0
        self.control_flow_counter = 0
        self.flow_type = flow_type
        self.current_token = None
        self.last_token = None
        self.next_depth_correlator = None

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
                # This could happend if the last control flow was a onliner
                break

            self.current_token = self.__next_token()  # Next token to correalate

            if not self.current_token:
                break  # End of correlation at current depth

            match self.current_token.token_type:
                # ----------------------- Handle assignment operations ----------------------- #
                case "OP0":  # FIXME: This is a temporary solution is it good?
                    if self.last_token and "VAR" in self.last_token.token_type:
                        self.__handle_assignment(self.last_token)

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

                # ---------------------- Handle possible vulnerabilities --------------------- #
                case "INPUT":
                    pass
                # XSS
                case "XSS_SENS":
                    self.__handle_assignment(self.current_token)
                case "XSS_SANF":
                    pass  # TODO handle SANF
                # SQLI
                case "SQLI_SENS":
                    pass
                case "SQLI_SANF":
                    pass

            self.last_token = self.current_token

    def __next_token(self):
        """Get the next token from the abstractor."""
        t = self.abstractor.token()
        if not t:
            return None
        return AbsToken(t.type, t.lineno, t.lexpos, self.depth, self.order, self.flow_type)

    def __handle_assignment(self, assignee: AbsToken):
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

            self.current_token = self.__next_token()

        if assignors:
            self.data_structure[assignee_name] = assignors

    def __correlate_next_depth(self, order: int, flow_type: int):
        if not self.next_depth_correlator:
            self.next_depth_correlator = Correlator(
                self.abstractor, self.data_structure, self.depth + 1, flow_type)
        self.next_depth_correlator.update(
            order, flow_type, self.current_token, self.last_token)
        self.next_depth_correlator.correlate()
