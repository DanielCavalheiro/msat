"""Module for the Correlator component"""

from components.abstractor import Abstractor
from utils.token_utils import AbsToken, FuncCallToken
from utils.scope_details import ScopeDetails


class Correlator:
    """Correlator component class to correlate abstracted tokens."""

    def __init__(self, abstractor: Abstractor, data_structure: dict, depth, flow_type, current_scope, scopes):
        self.abstractor = abstractor
        self.data_structure = data_structure
        self.depth = depth
        self.order = 0
        self.control_flow_counter = 0
        self.flow_type = flow_type
        self.current_token = None
        self.last_token = None
        self.next_depth_correlator = None

        self.current_scope = current_scope
        if current_scope not in self.data_structure:
            self.data_structure[current_scope] = {}
        self.scopes = scopes
        if current_scope not in self.scopes:
            self.scopes[current_scope] = ScopeDetails([], [])
        for argument in self.scopes[current_scope].arguments:
            self.data_structure[self.current_scope][argument.token_type] = []

        self.awating_func_call = {}
        self.awating_func_return = {}

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

            if self.last_token and self.last_token.token_type in ("END_CF", "END_FUNC"):
                # Leave the current depth/func
                break

            self.current_token = self.__next_token()  # Next token to correalate

            if not self.current_token:
                break  # End of correlation at current depth

            token_type = self.current_token.token_type

            # ----------------------- Handle assignment operations ----------------------- #
            if token_type == "OP0":  # FIXME: This is a temporary solution is it good?
                if self.last_token and "VAR" in self.last_token.token_type:
                    self.__handle_correlation(self.last_token)

            # --------------------------- Handle control flows --------------------------- #
            elif token_type == "IF":
                self.control_flow_counter += 1
                elseif_counter = 1  # starts at 1 because of the IF
                self.__correlate_next_depth(self.control_flow_counter, 1)

            elif token_type == "ELSE":
                self.__correlate_next_depth(self.control_flow_counter, -1)

            elif token_type == "ELSEIF":
                elseif_counter += 1
                self.__correlate_next_depth(
                    self.control_flow_counter, elseif_counter)

            elif token_type in ["WHILE", "FOR", "FOREACH", "SWITCH", "DO"]:
                self.control_flow_counter += 1
                self.__correlate_next_depth(self.control_flow_counter, 1)

            # ----------------------------- Handle functions ----------------------------- #
            elif token_type == "FUNCTION":
                self.__handle_func_defenition()

            elif "FUNC_CALL" in token_type:
                func_name = self.current_token.token_type.split(":", 1)[1]
                if func_name in self.scopes:
                    arguments = self.__handle_func_call(func_name)
                    func_calls = self.data_structure[self.current_scope].get(
                        "FUNC_CALL", [])
                    func_calls.append(FuncCallToken("FUNC_CALL", self.current_token.line_num, self.current_token.token_pos, self.depth,
                                      self.order, self.flow_type, self.current_scope, func_name, arguments, self.scopes[func_name].return_values))
                    self.data_structure[self.current_scope]["FUNC_CALL"] = func_calls
                    self.current_token = self.__next_token()  # Skip the RPAREN
                else:  # TODO: Handle function calls that are not defined
                    arguments = []
                    self.current_token = self.__next_token()
                    while self.current_token and self.current_token.token_type != "RPAREN":
                        arguments.append(self.current_token)
                        self.current_token = self.__next_token()

            elif token_type == "RETURN":
                self.__handle_func_return()

            # ---------------------- Handle possible vulnerabilities --------------------- #
            elif token_type == "INPUT":
                pass
            # XSS
            elif token_type == "XSS_SENS":
                self.__handle_correlation(self.current_token)
            elif token_type == "XSS_SANF":
                pass  # TODO: mysqli_stmt_bind_param
            # SQLI
            elif token_type == "SQLI_SENS":
                self.__handle_sqli_sens()
            elif token_type == "SQLI_SANF":
                pass

            self.last_token = self.current_token

    def __next_token(self):
        """Get the next token from the abstractor."""
        t = self.abstractor.token()
        if not t:
            return None
        return AbsToken(t.type, t.lineno, t.lexpos, self.depth, self.order, self.flow_type, self.current_scope)

    def __correlate_next_depth(self, order: int, flow_type: int):
        if not self.next_depth_correlator:
            self.next_depth_correlator = Correlator(
                self.abstractor, self.data_structure, self.depth + 1, flow_type, self.current_scope, self.scopes)
        self.next_depth_correlator.update(
            order, flow_type, self.current_token, self.last_token)
        self.next_depth_correlator.correlate()

    def __handle_correlation(self, assignee: AbsToken):
        """Handle assignment operations creating data flow."""
        assignee_name = assignee.token_type
        assignors = self.data_structure[self.current_scope].get(
            assignee_name, [])

        while self.current_token and self.current_token.token_type not in ("SEMI", "END_CF"):

            if "VAR" in self.current_token.token_type or self.current_token.token_type in ("ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT"):
                assignors.append(self.current_token)

            elif ("FUNC_CALL" in self.current_token.token_type):  # TODO - Handle function
                func_name = self.current_token.token_type.split(":", 1)[1]
                if func_name in self.scopes:
                    arguments = self.__handle_func_call(func_name)
                    assignors.append(FuncCallToken("FUNC_CALL", self.current_token.line_num, self.current_token.token_pos, self.depth,
                                     self.order, self.flow_type, self.current_scope, func_name, arguments, self.scopes[func_name].return_values))

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
            self.data_structure[self.current_scope][assignee_name] = assignors

    def __handle_func_defenition(self):
        self.current_token = self.__next_token()
        scope_name = self.current_token.token_type
        self.scopes[scope_name] = ScopeDetails([], [])
        self.current_token = self.__next_token()

        while self.current_token and self.current_token.token_type != "END_PARENS":
            self.current_token.scope = scope_name
            if "VAR" in self.current_token.token_type:
                self.scopes[scope_name].arguments.append(
                    self.current_token)
            self.current_token = self.__next_token()

        func_correlator = Correlator(
            self.abstractor, self.data_structure, self.depth, 0, scope_name, self.scopes)
        func_correlator.correlate()

    def __handle_func_return(self):
        """Handle function returns."""
        self.current_token = self.__next_token()
        func_details = self.scopes[self.current_scope]
        while self.current_token and self.current_token.token_type not in ("SEMI", "END_CF"):

            if "VAR" in self.current_token.token_type or self.current_token.token_type in ("ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT"):
                func_details.return_values.append(self.current_token)

            elif ("FUNC_CALL" in self.current_token.token_type):  # TODO - Handle function
                func_name = self.current_token.token_type.split(":", 1)[1]
                self.__handle_func_call(func_name)

            elif self.current_token.token_type == "INPUT":
                func_details.return_values.append(self.current_token)
                while (self.current_token and self.current_token.token_type != "RPAREN"):
                    self.current_token = self.__next_token()

            elif "_SANF" in self.current_token.token_type:
                func_details.return_values.append(self.current_token)
                while (self.current_token and self.current_token.token_type != "RPAREN"):
                    self.current_token = self.__next_token()

            elif "SQLI_SENS" == self.current_token.token_type:
                func_details.return_values.append(self.current_token)
                self.__handle_sqli_sens()

            self.current_token = self.__next_token()

        scope_returns = self.data_structure[self.current_scope].get(
            "RETURN", [])
        for return_value in func_details.return_values:
            scope_returns.append(return_value)

        self.data_structure[self.current_scope]["RETURN"] = scope_returns

    def __handle_func_call(self, func_name):
        """Handle function calls."""
        self.current_token = self.__next_token()
        arguments = []
        # FIXME: multiple tokens could come for the same argument :(
        for argument in self.scopes[func_name].arguments:

            if "VAR" in self.current_token.token_type or self.current_token.token_type in ("ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT"):
                arguments.append(self.current_token)

            elif ("FUNC_CALL" in self.current_token.token_type):
                # TODO - Function call within a function call
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif self.current_token.token_type == "INPUT":
                arguments.append(self.current_token)
                while (self.current_token and self.current_token.token_type != "RPAREN"):
                    self.current_token = self.__next_token()

            elif "_SANF" in self.current_token.token_type:
                arguments.append(self.current_token)
                while (self.current_token and self.current_token.token_type != "RPAREN"):
                    self.current_token = self.__next_token()

            elif "SQLI_SENS" == self.current_token.token_type:
                arguments.append(self.current_token)
                self.__handle_sqli_sens()

            return arguments

    def __handle_sqli_sens(self):
        """Handle SQL Injection sensitive operations."""
        sql_sens = self.data_structure[self.current_scope].get("SQLI_SENS", [])

        self.current_token = self.__next_token()
        while self.current_token and self.current_token.token_type != "RPAREN":
            sql_sens.append(self.current_token)
            self.current_token = self.__next_token()

        self.data_structure[self.current_scope]["SQLI_SENS"] = sql_sens
