"""Module for the Detector component"""

from utils.token_utils import EncToken
import utils.crypto_stuff as crypto_stuff


class Detector:
    """Detector component that detects vulnerabilities"""

    def __init__(self, data_structure, shared_password, encrypt_flag):
        self.data_structure = data_structure
        self.shared_password = shared_password
        if encrypt_flag:
            self.special_tokens = crypto_stuff.populate_special_tokens(
                shared_password)
        else:
            self.special_tokens = {"INPUT": "INPUT", "XSS_SENS": "XSS_SENS",
                                   "XSS_SANF": "XSS_SANF", "SQLI_SENS": "SQLI_SENS", "SQLI_SANF": "SQLI_SANF"}
        self.vuln_type = None

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

        detected_paths = {}
        for token in self.data_structure[query]:
            detected_paths_by_sink = []
            current_path = []
            visited = []
            visited.append(token)
            previous_pos = None
            self.__detect_flows(detected_paths_by_sink, current_path,
                                visited, token, previous_pos)
            detected_paths[token] = []
            for path in detected_paths_by_sink:
                detected_paths[token].append(path)

        # Check if there are any detected paths
        if not detected_paths:
            # No detected paths no vulnerabilities
            return []

        # Get best matches
        relevant_paths = []
        for sink, paths in detected_paths.items():
            best = None
            closest = None
            for i in range(0, max(len(path) for path in paths)):
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
                if token.depth > relevant_path[0].depth:
                    for path in detected_paths[relevant_path[0]]:
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

    def __detect_flows(self, detected_paths, current_path, visited, current_token: EncToken, previous_pos):
        """Recursive function to detect data flows that start at a input and end in a sensitive sink"""
        current_path.append(current_token)
        if current_token.token_type == self.special_tokens["INPUT"] or current_token.token_type not in self.data_structure:
            paths_to_remove = []
            for path in detected_paths:
                for i in range(0, min(len(path), len(current_path))):
                    if path[i] != current_path[i]:
                        if path[i].depth == current_path[i].depth and path[i].order == current_path[i].order and path[i].flow_type == current_path[i].flow_type:
                            if path[i].token_pos < current_path[i].token_pos:
                                paths_to_remove.append(path)
                            else:
                                paths_to_remove.append(current_path)
            detected_paths.append(current_path.copy())
            for path in paths_to_remove:
                detected_paths.remove(path)
        else:
            for token in self.data_structure[current_token.token_type]:
                if token not in visited and (not previous_pos or previous_pos > token.token_pos):
                    previous_pos = current_token.token_pos
                    visited.append(token)
                    self.__detect_flows(
                        detected_paths, current_path, visited, token, previous_pos)
                    current_path.pop()
                    visited.remove(token)
