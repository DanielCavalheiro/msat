"""Module for the Detector component"""

import utils.crypto_stuff as crypto_stuff
from utils.token_utils import AbsToken, ScopeChangeToken


class Detector:
    """Detector component that detects vulnerabilities"""

    def __init__(self, data_structure: dict, shared_password, encrypt_flag=True):
        self.data_structure = data_structure
        self.shared_password = shared_password
        if encrypt_flag:
            self.special_tokens = crypto_stuff.populate_special_tokens(
                shared_password)
        else:
            self.special_tokens = {"INPUT": "INPUT", "XSS_SENS": "XSS_SENS",
                                   "XSS_SANF": "XSS_SANF", "SQLI_SENS": "SQLI_SENS",
                                   "SQLI_SANF": "SQLI_SANF", "FUNC_CALL": "FUNC_CALL",
                                   "RETURN": "RETURN", "ARGS": "ARGS", "IMPORTS": "IMPORTS"}
        self.vuln_type = None

        self.analysed_function_calls = []

    def set_vuln_type(self, vuln_type: str):
        """Sets the vulnerability type"""
        self.vuln_type = vuln_type

    def detect_vulnerability(self):
        """Detects a vulnerability in the data structure"""

        # Detect data flows
        detected_paths = {}
        vul_query = self.special_tokens[self.vuln_type + "_SENS"]
        vul_query = crypto_stuff.hmac_it(vul_query, self.shared_password)
        fun_query = self.special_tokens["FUNC_CALL"]
        fun_query = crypto_stuff.hmac_it(fun_query, self.shared_password)
        args_query = self.special_tokens["ARGS"]
        args_query = crypto_stuff.hmac_it(args_query, self.shared_password)

        for scope_key, scope_values in self.data_structure.items():

            # Check if the scope has the sensitive sink
            if vul_query in scope_values:
                self.__detect_paths_in_scope(
                    scope_key, scope_values, vul_query, detected_paths)

            # Check all function calls have sensitive sinks in their scopes
            if fun_query in scope_values:
                for func_call in scope_values[fun_query]:
                    if func_call in self.analysed_function_calls:
                        continue
                    self.analysed_function_calls.append(func_call)
                    func_name_key = crypto_stuff.hmac_it(
                        func_call.scope_name, self.shared_password)
                    if func_name_key not in self.data_structure:
                        continue
                    func_scope = self.data_structure[func_name_key].copy(
                    )
                    call_args = func_call.arguments
                    for i, func_arg in enumerate(func_scope[args_query]):
                        if i >= len(call_args):
                            break  # Skip if there are more arguments in the function than in the call
                        call_arg = call_args[i]
                        if crypto_stuff.hmac_it(call_arg.token_type, self.shared_password) == fun_query:
                            arg = ScopeChangeToken(call_arg.token_type, call_arg.line_num, call_arg.token_pos,
                                                   func_arg.depth,
                                                   func_arg.order, func_arg.flow_type, func_arg.split, call_arg.scope,
                                                   call_arg.scope_name, call_arg.arguments)
                        else:
                            arg = AbsToken(call_arg.token_type, call_arg.line_num, call_arg.token_pos,
                                           func_arg.depth, func_arg.order, func_arg.flow_type, func_arg.split,
                                           call_arg.scope)
                        func_arg_key = crypto_stuff.hmac_it(
                            func_arg.token_type, self.shared_password)
                        func_arg_correlations = func_scope.get(
                            func_arg_key, [])
                        func_arg_correlations.append(arg)
                        func_scope[func_arg_key] = func_arg_correlations

                    if vul_query in func_scope:
                        self.__detect_paths_in_scope(
                            func_name_key, func_scope, vul_query, detected_paths)

        # Check if there are any detected paths
        if all(len(paths) == 0 for paths in detected_paths.values()):
            return []

        # Get best matches
        relevant_paths = self.__get_best_match(detected_paths)

        # Handle Control Flows
        candidate_paths = self.__handle_control_flows(
            detected_paths, relevant_paths)

        candidate_paths = self.__handle_splits(detected_paths, candidate_paths)

        # Check if paths ends in Input or has a Sanitization fuction
        result_paths = self.__get_vulnerable_paths(candidate_paths)

        return result_paths

    # ---------------------------------------------------------------------------- #
    #                              Auxiliar functions                              #
    # ---------------------------------------------------------------------------- #

    def __get_imports(self, scope_values):
        """Get the imports in a given scope"""
        import_query = crypto_stuff.hmac_it(self.special_tokens["IMPORTS"], self.shared_password)
        imports = scope_values.get(import_query, [])
        imports.sort(key=lambda x: x.token_pos, reverse=True)
        return imports

    def __detect_paths_in_scope(self, scope_key, scope_values, query, detected_paths):
        """Detects paths in a given scope"""

        for token in scope_values[query]:
            detected_paths_by_sink = []
            current_path = []
            visited = []
            visited.append(token)
            imports = self.__get_imports(scope_values)
            self.__detect_flows(scope_key, scope_values, detected_paths_by_sink, current_path, visited, token, imports)

            paths = detected_paths.get(token, [])
            for path in detected_paths_by_sink:
                paths.append(path)
            if len(paths) > 0:
                detected_paths[token] = paths

    def __detect_flows(self, scope_key, scope_values, detected_paths_by_sink, current_path, visited, current_token,
                       imports):
        """Recursive function to detect data flows that start at an input and end in a sensitive sink"""
        current_path.append(current_token)
        current_token_type_key = crypto_stuff.hmac_it(
            current_token.token_type, self.shared_password)
        func_call = self.special_tokens["FUNC_CALL"]
        if current_token.token_type == func_call:
            if current_token in self.analysed_function_calls:
                return
            self.analysed_function_calls.append(current_token)
            func_name_key = crypto_stuff.hmac_it(
                current_token.scope_name, self.shared_password)
            if func_name_key not in self.data_structure:
                return
            func_scope = self.data_structure[func_name_key].copy()
            call_args = current_token.arguments

            # Add func call arguments to the scope
            query = self.special_tokens["ARGS"]
            query = crypto_stuff.hmac_it(query, self.shared_password)
            for i, func_arg in enumerate(func_scope[query]):
                call_arg = call_args[i]
                if call_arg.token_type == func_call:
                    arg = ScopeChangeToken(call_arg.token_type, call_arg.line_num, call_arg.token_pos, func_arg.depth,
                                           func_arg.order, func_arg.flow_type, func_arg.split, call_arg.scope,
                                           call_arg.scope_name, call_arg.arguments)
                else:
                    arg = AbsToken(call_arg.token_type, call_arg.line_num, call_arg.token_pos,
                                   func_arg.depth, func_arg.order, func_arg.flow_type, func_arg.split, call_arg.scope)
                func_arg_key = crypto_stuff.hmac_it(
                    func_arg.token_type, self.shared_password)
                func_arg_correlations = func_scope.get(
                    func_arg_key, [])
                func_arg_correlations.append(arg)
                func_scope[func_arg_key] = func_arg_correlations

            # Recursively find flows in the function scope
            query = self.special_tokens["RETURN"]
            query = crypto_stuff.hmac_it(query, self.shared_password)
            imports = self.__get_imports(func_scope)
            if query not in func_scope:
                self.__conclude_path(current_path, detected_paths_by_sink)
            else:
                for token in func_scope[query]:
                    visited.append(token)
                    self.__detect_flows(func_name_key, func_scope, detected_paths_by_sink, current_path, visited, token,
                                        imports)
                    current_path.pop()
                    visited.remove(token)

        elif current_token_type_key not in scope_values:
            current_token_scope_key = crypto_stuff.hmac_it(
                current_token.scope, self.shared_password)
            # if the current token is an input then path must conclude immediate
            if current_token.token_type == self.special_tokens["INPUT"]:
                self.__conclude_path(current_path, detected_paths_by_sink)
            # if the current token scope is different to the current scope must find the token in the other scope
            elif current_token_scope_key != scope_key:
                scope_values = self.data_structure[current_token_scope_key]
                imports = self.__get_imports(scope_values)
                if current_token_type_key not in scope_values:
                    self.__conclude_path(current_path, detected_paths_by_sink)
                else:
                    for token in scope_values[current_token_type_key]:
                        if token not in visited and (
                                not current_token or current_token.scope != token.scope or current_token.token_pos > token.token_pos):
                            visited.append(token)
                            found_in_import = False
                            for import_token in imports:
                                if token.token_pos < import_token.token_pos < current_token.token_pos:
                                    import_scope_key = crypto_stuff.hmac_it(import_token.scope_name, self.shared_password)
                                    if import_scope_key not in self.data_structure:
                                        continue
                                    import_scope = self.data_structure[import_scope_key]
                                    if current_token_type_key not in import_scope:
                                        continue
                                    found_in_import = True

                                    imports = self.__get_imports(import_scope)
                                    for token in import_scope[current_token_type_key]:
                                        if token not in visited and (
                                                not current_token or current_token.scope != token.scope or current_token.token_pos > token.token_pos):
                                            visited.append(token)
                                            self.__detect_flows(import_scope_key, import_scope, detected_paths_by_sink,
                                                                current_path,
                                                                visited, token, imports)
                                            current_path.pop()
                                            visited.remove(token)
                                if found_in_import:
                                    break
                            if found_in_import:
                                continue
                            self.__detect_flows(current_token_scope_key, scope_values, detected_paths_by_sink, current_path,
                                                visited, token, imports)
                            current_path.pop()
                            visited.remove(token)
            else:
                if imports:
                    found_in_import = False
                    for import_token in imports:
                        if import_token.token_pos > current_token.token_pos:
                            continue
                        import_scope_key = crypto_stuff.hmac_it(import_token.scope_name, self.shared_password)
                        if import_scope_key not in self.data_structure:
                            continue
                        import_scope = self.data_structure[import_scope_key]
                        if current_token_type_key not in import_scope:
                            continue
                        found_in_import = True
                        imports = self.__get_imports(import_scope)
                        for token in import_scope[current_token_type_key]:
                            visited.append(token)
                            self.__detect_flows(import_scope_key, import_scope, detected_paths_by_sink, current_path,
                                                visited, token, imports)
                            current_path.pop()
                            visited.remove(token)
                        break
                    if not found_in_import:
                        self.__conclude_path(current_path, detected_paths_by_sink)

                else:
                    self.__conclude_path(current_path, detected_paths_by_sink)

        else:
            for token in scope_values[current_token_type_key]:
                if token not in visited and (
                        not current_token or current_token.scope != token.scope or current_token.token_pos > token.token_pos):
                    visited.append(token)
                    found_in_import = False
                    for import_token in imports:
                        if token.token_pos < import_token.token_pos < current_token.token_pos:
                            import_scope_key = crypto_stuff.hmac_it(import_token.scope_name, self.shared_password)
                            if import_scope_key not in self.data_structure:
                                continue
                            import_scope = self.data_structure[import_scope_key]
                            if current_token_type_key not in import_scope:
                                continue
                            found_in_import = True

                            imports = self.__get_imports(import_scope)
                            for token in import_scope[current_token_type_key]:
                                if token not in visited and (
                                        not current_token or current_token.scope != token.scope or current_token.token_pos > token.token_pos):
                                    visited.append(token)
                                    self.__detect_flows(import_scope_key, import_scope, detected_paths_by_sink,
                                                        current_path,
                                                        visited, token, imports)
                                    current_path.pop()
                                    visited.remove(token)
                        if found_in_import:
                            break
                    if found_in_import:
                        continue
                    self.__detect_flows(scope_key, scope_values, detected_paths_by_sink, current_path, visited, token,
                                        imports)
                    current_path.pop()
                    visited.remove(token)

    def __conclude_path(self, current_path, detected_paths_by_sink):
        """Conclude the current path"""
        paths_to_remove = []
        for path in detected_paths_by_sink:
            for i in range(0, min(len(path), len(current_path))):
                if path[i] != current_path[i]:
                    if path[i].depth == current_path[i].depth and path[i].order == current_path[i].order and path[
                        i].flow_type == current_path[i].flow_type and path[i].scope == current_path[i].scope and path[
                        0].split == current_path[i].split:
                        if path[i].token_pos < current_path[i].token_pos:
                            paths_to_remove.append(path)
                            break
                        else:
                            paths_to_remove.append(current_path)
                            break
                    else:
                        break
        detected_paths_by_sink.append(current_path.copy())
        for path in paths_to_remove:
            detected_paths_by_sink.remove(path)

    def __get_best_match(self, detected_paths):
        """get the path that is closest to each sink"""
        relevant_paths = []
        for _, paths in detected_paths.items():
            paths_to_analyse = paths.copy()
            for path in paths:
                if len(path) == 1:
                    relevant_paths.append(path)
                    paths_to_analyse.remove(path)
            best = None
            closest = None
            if paths_to_analyse:
                for i in range(1, max(len(path) for path in paths_to_analyse)):
                    for current_path in paths:
                        if i < len(current_path):
                            current_token = current_path[i]
                            current_sink = current_path[0]
                            if closest is None:
                                closest = current_path[i]
                                best = current_path
                            if current_token.scope != current_sink.scope:
                                continue
                            elif current_sink.token_pos - current_token.token_pos < current_sink.token_pos - closest.token_pos:
                                closest = current_path[i]
                                best = current_path
            if best:
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
                                    break
                                elif current_token.order == token.order and current_token.flow_type != token.flow_type:
                                    candidate_paths.append(path)
                                    break
                                elif current_token.order == token.order and current_token.flow_type == token.flow_type and current_token.depth != token.depth:
                                    candidate_paths.append(path)
                                    break

        return candidate_paths

    def __handle_splits(self, detected_paths, candidate_paths):
        """check if there are any splits that need to be considered"""
        for candidate_path in candidate_paths:
            for i, token in enumerate(candidate_path):
                if token.split != candidate_path[0].split:
                    for path in detected_paths[candidate_path[0]]:
                        if path in candidate_paths:
                            continue
                        j = 0
                        while j <= i:
                            if j < min(len(path), len(candidate_path)) and path[j] != candidate_path[j] and path[
                                j].split == candidate_path[j].split:
                                candidate_paths.append(path)
                                break
                            j += 1

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
