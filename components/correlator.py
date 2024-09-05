"""Module for the Correlator component"""

from components.abstractor import Abstractor
from utils.token_utils import AbsToken, ScopeChangeToken


class Correlator:
    """Correlator component class to correlate abstracted tokens."""

    def __init__(self, abstractor: Abstractor, data_structure: dict, depth, flow_type, current_scope, scopes, split_counter=0):
        self.abstractor = abstractor  # Abstractor object to get the tokens
        self.data_structure = data_structure  # dictionary where correlations are stored (assignments/function calls)
        self.depth = depth  # depth of the current token (how deep in control flow)
        self.order = 0  # order of the current token (two different control flows in same depth have diff orders)
        self.control_flow_counter = 0  # counter for control flows in depth
        self.flow_type = flow_type  # type of control flow (1: simple, -1: else, 0: no control flow ...)
        self.current_token = None  # current token being correlated
        self.last_token = None  # last token correlated
        self.next_depth_correlator = None  # the correlator for the next depth (singleton)
        self.split_counter = split_counter  # split counter

        self.current_scope = current_scope  # current scope (file/function) being correlated
        if current_scope not in self.data_structure:
            self.data_structure[current_scope] = {}  # Create a new scope in the data structure

        self.scopes = scopes  # Dict to store the funcs of this scope and their args
        if current_scope not in self.scopes:
            self.scopes[current_scope] = []

        # save the arguments of the current scope (only functions will have arguments)
        arguments = self.data_structure[self.current_scope].get("ARGS", [])
        for argument in self.scopes[current_scope]:
            if argument not in arguments:
                arguments.append(argument)
        self.data_structure[self.current_scope]["ARGS"] = arguments

    def update(self, order, flow_type, current_token, last_token):
        """Update the correlator with new order and flow type."""
        self.order = order
        self.flow_type = flow_type
        self.current_token = current_token
        self.last_token = last_token

    def correlate(self):
        """Correlate the abstracted tokens."""
        elseif_counter = 0  # counter for else ifs

        while True:  # Iterate over the tokens

            if self.last_token and self.last_token.token_type in ("END_CF", "END_FUNC"):
                # Leave the current depth/func
                break

            self.current_token = self.__next_token()  # Next token to correlate

            if not self.current_token:
                break  # End of correlation at current depth

            token_type = self.current_token.token_type  # Type of the current token

            # ----------------------- Handle assignment operations ----------------------- #
            if token_type == "OP0":  # FIXME: This is a temporary solution is it good?
                # Handle assignment operations key will be the last token and  value will be all tokens until semicolon
                if self.last_token and "VAR" in self.last_token.token_type:
                    self.__handle_correlation(self.last_token)

            # --------------------------- Handle control flows --------------------------- #
            elif token_type == "IF":
                # Start a new control flow and correlate the next depth
                self.control_flow_counter += 1
                elseif_counter = 1  # starts at 1 because of the IF
                self.__correlate_next_depth(self.control_flow_counter, 1)

            elif token_type == "ELSE":
                # Start a new control flow and correlate the next depth
                self.__correlate_next_depth(self.control_flow_counter, -1)

            elif token_type in ("ELSEIF", "CASE"):
                # Start a new control flow and correlate the next depth
                elseif_counter += 1
                self.__correlate_next_depth(self.control_flow_counter, elseif_counter)

            elif token_type in ["WHILE", "FOR", "FOREACH", "SWITCH", "DO"]:
                # Start a new control flow and correlate the next depth
                self.control_flow_counter += 1
                self.__correlate_next_depth(self.control_flow_counter, 1)

            # ----------------------------- Handle functions ----------------------------- #
            elif token_type == "FUNCTION":
                self.__handle_func_definition()

            elif "FUNC_CALL" in token_type:
                # Handle function calls
                func_name = self.current_token.token_type.split(":", 1)[1]
                arguments = self.__handle_func_call()
                self.data_structure[self.current_scope].setdefault("FUNC_CALL", []).append(
                    ScopeChangeToken("FUNC_CALL", self.current_token.line_num, self.current_token.token_pos, self.depth,
                                     self.order, self.flow_type, 0, self.current_scope, func_name, arguments))

            elif token_type == "RETURN":
                # Handle return of a function
                self.__handle_correlation(self.current_token)

            # ----------------------------- Handle Imports ------------------------------- #
            elif token_type == "IMPORT":
                # Import of a different file must be saved in data structure
                self.__handle_import()

            # ---------------------- Handle possible vulnerabilities --------------------- #
            elif token_type == "INPUT":
                # Don't think will enter here
                pass
            # XSS
            elif token_type == "XSS_SENS":
                self.__handle_xss_sens(self.current_token)
            elif token_type == "XSS_SANF":
                pass  # TODO: mysqli_stmt_bind_param? or maybe not
            # SQLI
            elif token_type == "SQLI_SENS":
                self.__handle_sqli_sens()
            elif token_type == "SQLI_SANF":
                # won't happen
                pass

            self.last_token = self.current_token  # update last token

    # ---------------------------------------------------------------------------- #
    #                              Auxiliary functions                             #
    # ---------------------------------------------------------------------------- #

    def __next_token(self):
        """Get the next token from the abstractor."""
        t = self.abstractor.token()
        if not t:
            return None
        return AbsToken(t.type, t.lineno, t.lexpos, self.depth, self.order, self.flow_type, 0, self.current_scope)

    def __correlate_next_depth(self, order: int, flow_type: int):
        """correlate the next depth (control flow) in code """
        if not self.next_depth_correlator:
            self.next_depth_correlator = Correlator(self.abstractor, self.data_structure, self.depth + 1, flow_type,
                                                    self.current_scope, self.scopes, self.split_counter)
        self.next_depth_correlator.update(order, flow_type, self.current_token, self.last_token)
        self.next_depth_correlator.correlate()

    def __handle_correlation(self, assignee: AbsToken):
        """Handle assignment operations creating data flow."""
        assignee_name = assignee.token_type
        assignors = self.data_structure[self.current_scope].get(assignee_name, [])

        while self.current_token and self.current_token.token_type not in ("SEMI", "END_CF", "END_PARENS"):

            if "VAR" in self.current_token.token_type or self.current_token.token_type in (
                    "ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT"):
                assignors.append(self.current_token)

            elif self.current_token.token_type == "CONCAT":
                # Handle concatenation as if it was a control flow to differentiate it from other paths
                self.split_counter = self.abstractor.lexpos
                if assignors:
                    assignors[-1].split = self.split_counter
                    self.__split_correlate(assignors)
                else:
                    while self.current_token and self.current_token.token_type not in ("SEMI", "END_CF"):
                        self.current_token = self.__next_token()
                break

            elif self.current_token.token_type == "QUOTE":
                # Handle Encased and whitespace strings as if it was a control flow to differentiate it from other path
                self.split_counter = self.abstractor.lexpos
                self.__split_correlate(assignors)
                break

            elif "FUNC_CALL" in self.current_token.token_type:
                func_name = self.current_token.token_type.split(":", 1)[1]  # get the function name
                arguments = self.__handle_func_call()
                # create a new scope change token for the function call
                scope_change_token = ScopeChangeToken("FUNC_CALL", self.current_token.line_num,
                                                      self.current_token.token_pos, self.depth,
                                                      self.order, self.flow_type, 0, self.current_scope, func_name,
                                                      arguments)
                assignors.append(scope_change_token)
                self.data_structure[self.current_scope].setdefault("FUNC_CALL", []).append(scope_change_token)

            elif self.current_token.token_type == "INPUT":
                assignors.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif "_SANF" in self.current_token.token_type:
                assignors.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif "SQLI_SENS" == self.current_token.token_type:
                assignors.append(self.current_token)
                self.__handle_sqli_sens()

            self.current_token = self.__next_token()

        if assignors:
            self.data_structure[self.current_scope][assignee_name] = assignors

    def __split_correlate(self, assignors):
        """Correlate the concatenation operation."""
        # every token that is found will have a different depth so that when the detector finds this it will treat the
        # token as a different data flow
        self.current_token = self.__next_token()
        self.current_token.split = self.split_counter
        while self.current_token and self.current_token.token_type not in ("SEMI", "END_CF"):

            if "VAR" in self.current_token.token_type or self.current_token.token_type in (
                    "ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT"):
                assignors.append(self.current_token)

            elif "_SANF" in self.current_token.token_type:
                assignors.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif "FUNC_CALL" in self.current_token.token_type:
                func_name = self.current_token.token_type.split(":", 1)[1]
                arguments = self.__handle_func_call()
                scope_change_token = ScopeChangeToken("FUNC_CALL", self.current_token.line_num,
                                                      self.current_token.token_pos, self.depth,
                                                      self.order, self.flow_type, 0, self.current_scope, func_name,
                                                      arguments)
                assignors.append(scope_change_token)
                self.data_structure[self.current_scope].setdefault("FUNC_CALL", []).append(scope_change_token)

            elif self.current_token.token_type == "INPUT":
                assignors.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            self.current_token = self.__next_token()
            self.current_token.split = self.split_counter

    # --------------------------------- functions -------------------------------- #

    def __handle_func_definition(self):
        """Correlates function scope"""
        self.current_token = self.__next_token()
        scope_name = self.current_token.token_type
        self.scopes[scope_name] = []
        self.current_token = self.__next_token()

        # adds scope arguments to the scopes variable so that the arguments can be used in the function
        while self.current_token and self.current_token.token_type != "END_PARENS":
            self.current_token.scope = scope_name
            if "VAR" in self.current_token.token_type:
                self.scopes[scope_name].append(self.current_token)
            self.current_token = self.__next_token()

        # Correlate the entire function scope
        func_correlator = Correlator(self.abstractor, self.data_structure, self.depth, 0, scope_name, self.scopes)
        func_correlator.correlate()

    def __handle_func_call(self):
        """Handle function calls."""
        # returns the arguments of the function call
        self.current_token = self.__next_token()
        arguments = []
        # TODO: multiple tokens could come for the same argument :( like a sting with variables in it
        while self.current_token and self.current_token.token_type != "END_PARENS":

            if "VAR" in self.current_token.token_type or self.current_token.token_type in (
                    "ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT", "STRING"):
                arguments.append(self.current_token)

            elif "FUNC_CALL" in self.current_token.token_type:
                func_name = self.current_token.token_type.split(":", 1)[1]
                inner_func_arguments = self.__handle_func_call()
                scope_change_token = ScopeChangeToken("FUNC_CALL", self.current_token.line_num,
                                                      self.current_token.token_pos, self.depth,
                                                      self.order, self.flow_type, 0, self.current_scope, func_name,
                                                      inner_func_arguments)
                arguments.append(scope_change_token)
                self.data_structure[self.current_scope].setdefault("FUNC_CALL", []).append(scope_change_token)

            elif self.current_token.token_type == "INPUT":
                arguments.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif "_SANF" in self.current_token.token_type:
                arguments.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif "SQLI_SENS" == self.current_token.token_type:
                arguments.append(self.current_token)
                self.__handle_sqli_sens()

            self.current_token = self.__next_token()

        return arguments

    # ------------------------------ Imports ------------------------------------- #
    def __handle_import(self):
        """Handle import statements (require/include)."""
        current_token = self.abstractor.token()
        while current_token and current_token.type != "SEMI":
            if current_token.type in ("CONSTANT_ENCAPSED_STRING", "ENCAPSED_AND_WHITESPACE"):
                token = ScopeChangeToken("IMPORT", current_token.lineno, current_token.lexpos, self.depth, self.order,
                                         self.flow_type, 0, self.current_scope, current_token.value, [])
                self.data_structure[self.current_scope].setdefault("IMPORTS", []).append(token)
            current_token = self.abstractor.token()

    # ------------------------------ vulnerabilities ------------------------------ #

    def __handle_xss_sens(self, assignee: AbsToken):
        """Handle assignment operations creating data flow."""
        assignee_name = assignee.token_type
        assignors = self.data_structure[self.current_scope].get(assignee_name, [])

        while self.current_token and self.current_token.token_type not in ("SEMI", "END_CF"):

            if "VAR" in self.current_token.token_type or self.current_token.token_type in (
                    "ENCAPSED_AND_WHITESPACE", "CONSTANT_ENCAPSED_STRING", "LNUMBER", "DNUMBER", "INPUT"):
                assignors.append(self.current_token)

            elif "FUNC_CALL" in self.current_token.token_type:
                func_name = self.current_token.token_type.split(":", 1)[1]
                arguments = self.__handle_func_call()
                scope_change_token = ScopeChangeToken("FUNC_CALL", self.current_token.line_num,
                                                      self.current_token.token_pos, self.depth,
                                                      self.order, self.flow_type, 0, self.current_scope, func_name,
                                                      arguments)
                assignors.append(scope_change_token)
                self.data_structure[self.current_scope].setdefault("FUNC_CALL", []).append(scope_change_token)

            elif self.current_token.token_type == "INPUT":
                assignors.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif "_SANF" in self.current_token.token_type:
                assignors.append(self.current_token)
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            self.current_token = self.__next_token()

        if assignors:
            self.data_structure[self.current_scope][assignee_name] = assignors

    def __handle_sqli_sens(self):
        """Handle SQL Injection sensitive operations."""
        sql_sens = self.data_structure[self.current_scope].get("SQLI_SENS", [])

        self.current_token = self.__next_token()
        while self.current_token and self.current_token.token_type != "RPAREN":
            if "SQLI_SANF" == self.current_token.token_type:
                while self.current_token and self.current_token.token_type != "RPAREN":
                    self.current_token = self.__next_token()

            elif "FUNC_CALL" in self.current_token.token_type:
                while self.current_token and self.current_token.token_type != "END_PARENS":
                    self.current_token = self.__next_token()
            else:
                sql_sens.append(self.current_token)
            self.current_token = self.__next_token()


        self.data_structure[self.current_scope]["SQLI_SENS"] = sql_sens
