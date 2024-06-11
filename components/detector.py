"""Module for the Detector component"""

import utils.crypto_stuff as crypto_stuff
from utils.token_utils import AbsToken


class Detector:
    """Detector component that detects vulnerabilities"""

    def __init__(self, data_structure: dict, shared_password, encrypt_flag):
        self.data_structure = data_structure
        self.shared_password = shared_password
        if encrypt_flag:
            self.special_tokens = crypto_stuff.populate_special_tokens(
                shared_password)
        else:
            self.special_tokens = {"INPUT": "INPUT", "XSS_SENS": "XSS_SENS",
                                   "XSS_SANF": "XSS_SANF", "SQLI_SENS": "SQLI_SENS",
                                   "SQLI_SANF": "SQLI_SANF", "FUNC_CALL": "FUNC_CALL",
                                   "RETURN": "RETURN", "ARGS": "ARGS"}
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

        # FIXME: This is a temporary solution
        scope = self.data_structure[next(
            iter(self.data_structure))]

        if query not in scope:
            return []

        # Detect data flows
        detected_paths = {}
        self.__detect_paths_in_scope(scope, query, detected_paths)

        # Check if there are any detected paths
        if all(len(paths) == 0 for paths in detected_paths.values()):
            return []

            # Get best matches
        relevant_paths = self.__get_best_match(detected_paths)

        # Handle Control Flows
        candidate_paths = self.__handle_control_flows(
            detected_paths, relevant_paths)

        # Check if paths ends in Input or has a Sanitization fuction
        result_paths = self.__get_vulnerable_paths(candidate_paths)

        return result_paths

    # ---------------------------------------------------------------------------- #
    #                              Auxiliar functions                              #
    # ---------------------------------------------------------------------------- #

    def __detect_paths_in_scope(self, scope, query, detected_paths):
        """Detects paths in a given scope"""

        for token in scope[query]:
            detected_paths_by_sink = []
            current_path = []
            visited = []
            visited.append(token)
            previous_pos = None
            self.__detect_flows(scope, detected_paths_by_sink, current_path,
                                visited, token, previous_pos)
            detected_paths[token] = []
            for path in detected_paths_by_sink:
                detected_paths[token].append(path)

    def __detect_flows(self, scope, detected_paths_by_sink, current_path, visited, current_token, previous_token):
        """Recursive function to detect data flows that start at a input and end in a sensitive sink"""
        current_path.append(current_token)

        if current_token.token_type == self.special_tokens["FUNC_CALL"]:
            previous_token = current_token
            scope = self.data_structure[current_token.func_name]
            call_args = current_token.arguments

            query = self.special_tokens["ARGS"]
            for i, func_arg in enumerate(scope[query]):
                arg = call_args[i]
                scope[func_arg.token_type].append(
                    AbsToken(arg.token_type, func_arg.line_num, func_arg.token_pos, func_arg.depth, func_arg.order, func_arg.flow_type, func_arg.scope))

            query = self.special_tokens["RETURN"]
            for token in scope[query]:
                visited.append(token)
                self.__detect_flows(
                    scope, detected_paths_by_sink, current_path, visited, token, previous_token)
                current_path.pop()
                visited.remove(token)
        elif current_token.token_type == self.special_tokens["INPUT"] or current_token.token_type not in scope:
            paths_to_remove = []
            for path in detected_paths_by_sink:
                for i in range(0, min(len(path), len(current_path))):
                    if path[i] != current_path[i]:
                        if path[i].depth == current_path[i].depth and path[i].order == current_path[i].order and path[i].flow_type == current_path[i].flow_type and path[i].scope == current_path[i].scope:
                            if path[i].token_pos < current_path[i].token_pos:
                                paths_to_remove.append(path)
                            else:
                                paths_to_remove.append(current_path)
            detected_paths_by_sink.append(current_path.copy())
            for path in paths_to_remove:
                detected_paths_by_sink.remove(path)
        else:
            for token in scope[current_token.token_type]:
                if token not in visited and (not previous_token or previous_token.scope != token.scope or previous_token.token_pos > token.token_pos):
                    previous_token = current_token
                    visited.append(token)
                    self.__detect_flows(
                        scope, detected_paths_by_sink, current_path, visited, token, previous_token)
                    current_path.pop()
                    visited.remove(token)

    def __get_best_match(self, detected_paths):
        """get the path that is closest to each sink"""
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

        return relevant_paths

    def __handle_control_flows(self, detected_paths, relevant_paths):
        """check if there are any control flows that need to be considered"""
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

        return candidate_paths

    def __get_vulnerable_paths(self, candidate_paths):
        """Get the paths that end in a user input"""
        result_paths = []
        for candidate_path in candidate_paths:
            for token in candidate_path:
                if token.token_type == self.special_tokens[self.vuln_type + "_SANF"]:
                    break
                if token.token_type == self.special_tokens["INPUT"]:
                    result_paths.append(candidate_path)
                    break

        return result_paths
