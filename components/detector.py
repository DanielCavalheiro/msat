"""Module for the Detector component"""

import utils.crypto_stuff as crypto_stuff
from utils.token_utils import EncToken


class Detector:
    """Detector component that detects vulnerabilities"""

    def __init__(self, data_structure, shared_password):
        self.data_structure = data_structure
        self.shared_password = shared_password
        self.special_tokens = self.__populate_special_tokens()
        self.current_path = []  # Current path being analyzedS
        self.paths = []  # Paths that have been analyzed
        self.paths_by_sink = {}  # Paths grouped by sink
        self.visited = []  # Tokens that have been visited

    def __populate_special_tokens(self):
        """Populate the special tokens"""
        return {
            "INPUT": crypto_stuff.hmac_it("INPUT", self.shared_password),
            "XSS_SENS": crypto_stuff.hmac_it("XSS_SENS", self.shared_password),
            "XSS_SANF": crypto_stuff.hmac_it("XSS_SANF", self.shared_password),
            "SQLI_SENS": crypto_stuff.hmac_it("SQLI_SENS", self.shared_password),
            "SQLI_SANF": crypto_stuff.hmac_it("SQLI_SANF", self.shared_password),
        }

    def detect_vulnerability(self, vuln_type: str):
        """Detects a vulnerability in the data structure"""
        if vuln_type not in self.special_tokens:
            return []
        query = self.special_tokens[vuln_type]
        if query not in self.data_structure:
            return []

        self.paths = []
        self.current_path = []
        self.visited = []
        for token in self.data_structure[query]:
            self.visited.append(token.token_type)
            self.__detect_flows(token)

        self.__group_by_sink()

    def __detect_flows(self, current_token: EncToken):
        """Recursive function to detect data flows that start at a input and end in a sensitive sink"""
        self.current_path.append(current_token)
        if current_token.token_type == self.special_tokens["INPUT"] or current_token.token_type not in self.data_structure:
            self.paths.append(self.current_path.copy())
        else:
            for token in self.data_structure[current_token.token_type]:
                if token.token_type not in self.visited:
                    self.visited.append(token.token_type)
                    self.__detect_flows(token)
                    self.current_path.pop()
                    self.visited.remove(token.token_type)

    def __group_by_sink(self):
        """Group paths by sink"""
        for path in self.paths:
            sink = path[0]
            if sink not in self.paths_by_sink:
                self.paths_by_sink[sink] = []
            self.paths_by_sink[sink].append(path)

    # def __filter_paths(self):
    #     """Filter paths that are not relevant"""
    #     relevant_paths = []
    #     for path in self.paths:
    #         for i in
