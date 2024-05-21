"""Module for the Detector component"""

import utils.crypto_stuff as crypto_stuff
from utils.token_utils import EncToken


class Detector:
    """Detector component that detects vulnerabilities"""

    def __init__(self, data_structure, shared_password):
        self.data_structure = data_structure
        self.shared_password = shared_password
        self.special_tokens = self.__populate_special_tokens()
        self.vuln_type = None

    def __populate_special_tokens(self):
        """Populate the special tokens"""
        return {
            "INPUT": crypto_stuff.hmac_it("INPUT", self.shared_password),
            "XSS_SENS": crypto_stuff.hmac_it("XSS_SENS", self.shared_password),
            "XSS_SANF": crypto_stuff.hmac_it("XSS_SANF", self.shared_password),
            "SQLI_SENS": crypto_stuff.hmac_it("SQLI_SENS", self.shared_password),
            "SQLI_SANF": crypto_stuff.hmac_it("SQLI_SANF", self.shared_password),
        }

    def set_vuln_type(self, vuln_type: str):
        """Sets the vulnerability type"""
        self.vuln_type = vuln_type

    def detect_vulnerability(self):
        """Detects a vulnerability in the data structure"""
        query = self.vuln_type + "_SENS"
        if query not in self.special_tokens:
            return []
        query = self.special_tokens[query]
        if query not in self.data_structure:
            return []

        detected_paths = []
        for token in self.data_structure[query]:
            current_path = []
            visited = []
            visited.append(token)
            self.__detect_flows(detected_paths, current_path, visited, token)

        # Group paths by sink
        paths_by_sink = {}
        for path in detected_paths:
            sink = path[0]
            if sink not in paths_by_sink:
                paths_by_sink[sink] = []
            paths_by_sink[sink].append(path)

        # Remove impossible paths
        possible_paths_by_sink = {}
        for sink, paths in paths_by_sink.items():
            possible_paths = []
            for path in paths:
                previous_pos = None
                for token in path:
                    if previous_pos is None:
                        previous_pos = token.token_pos
                    elif previous_pos > token.token_pos:
                        possible_paths.append(path)
                        break
                    previous_pos = token.token_pos
            possible_paths_by_sink[sink] = possible_paths

        # TODO: what if there are no possible paths?

        # Get best matches
        relevant_paths = []
        for sink, paths in possible_paths_by_sink.items():
            best = None
            closest = None
            for i in range(1, max(len(path) for path in paths)):
                for current_path in paths:
                    if i < len(current_path):
                        current_token = current_path[i]
                        current_sink = current_path[0]
                        if closest is None:
                            closest = current_path[i]
                            best = current_path
                        elif current_sink.token_pos - current_token.token_pos <= current_sink.token_pos - closest.token_pos:
                            closest = current_path[i]
                            best = current_path
            relevant_paths.append(best)

        # Handle Control Flows
        candidate_paths = relevant_paths.copy()
        for relevant_path in relevant_paths:
            for token in relevant_path:
                if token.depth > 0:
                    for path in paths_by_sink[relevant_path[0]]:
                        if path in candidate_paths:
                            continue
                        for current_token in path:
                            if current_token.token_pos <= token.token_pos:
                                if current_token.order != token.order:
                                    candidate_paths.append(path)
                                elif current_token.order == token.order and current_token.flow_type != token.flow_type:
                                    candidate_paths.append(path)
                                elif current_token.order == token.order and current_token.flow_type == token.flow_type and current_token.depth != token.depth:
                                    candidate_paths.append(path)

        # Check if path ends in Input or has a Sanitization fuction
        result_paths = []
        for candidate_path in candidate_paths:
            for token in candidate_path:
                if token.token_type == self.special_tokens[self.vuln_type + "_SANF"]:
                    break

                if token.token_type == self.special_tokens["INPUT"]:
                    result_paths.append(candidate_path)
                    break

        return result_paths

    def __detect_flows(self, detected_paths, current_path, visited, current_token: EncToken):
        """Recursive function to detect data flows that start at a input and end in a sensitive sink"""
        current_path.append(current_token)
        if current_token.token_type == self.special_tokens["INPUT"] or current_token.token_type not in self.data_structure:
            detected_paths.append(current_path.copy())
        else:
            for token in self.data_structure[current_token.token_type]:
                if token not in visited:
                    visited.append(token)
                    self.__detect_flows(
                        detected_paths, current_path, visited, token)
                    current_path.pop()
                    visited.remove(token)
