import base64
import json
import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from utils.token_utils import ResultToken, token_decoder, result_decoder
import utils.crypto_stuff as crypto_stuff


def decrypt_token(token, secret_password, special_tokens):
    """Decrypts an encrypted token."""
    if token.token_type == special_tokens["INPUT"]:
        token_type = "INPUT"
    elif token.token_type == special_tokens["FUNC_CALL"]:
        token_type = "FUNC_CALL"
    else:
        token_type = crypto_stuff.decrypt_sse(
            base64.b64decode(token.token_type), secret_password)
    line_num = crypto_stuff.decrypt_sse(
        base64.b64decode(token.line_num), secret_password)
    position = crypto_stuff.decrypt_ope(token.token_pos, secret_password)
    scope = crypto_stuff.decrypt_sse(
        base64.b64decode(token.scope), secret_password)
    if token.arguments is not None:
        scope_name = crypto_stuff.decrypt_sse(
            base64.b64decode(token.scope_name), secret_password)
        arguments = []
        for arg in token.arguments:
            arguments.append(decrypt_token(arg, secret_password, special_tokens))
        return ResultToken(token_type, line_num, position, scope, scope_name, arguments)
    elif token.scope_name is not None:
        scope_name = crypto_stuff.decrypt_sse(
            base64.b64decode(token.scope_name), secret_password)
        return ResultToken(token_type, line_num, position, scope, scope_name)

    return ResultToken(token_type, line_num, position, scope)


def main(secret_password, shared_password, file):
    secret_password = crypto_stuff.generate_key(secret_password)
    shared_password = crypto_stuff.generate_key(shared_password)

    if not os.path.exists(file):
        error = f"{file} does not exist"
        print(error)
        return 0, error

    result_message = ""
    try:
        with open(file, "r", encoding="utf-8") as f:
            decrypted_data = crypto_stuff.decrypt_gcm(f.read(), shared_password)
            vulnerable_paths = json.loads(decrypted_data, object_hook=result_decoder)
            special_tokens = crypto_stuff.populate_special_tokens(shared_password)
            path_counter = 0
            if not vulnerable_paths:
                result_message = "No vulnerable paths detected."
            else:
                result_message = "Decryption completed successfully!\nPrinting vulnerable paths.\nThe first token in each path reach a vulnerable sink.\n\n"
                for path in vulnerable_paths:
                    path_counter += 1
                    result_message = result_message + f"\nVulnerable path {path_counter}:\n"
                    for i, token in enumerate(path):
                        result_message = result_message + "\t" + str(i) + ". " + str(
                            decrypt_token(token, secret_password, special_tokens)) + "\n"
                    result_message = result_message + "\n"
    except Exception as e:
        error = f"Error: {e}"
        print(error)
        return 0, error

    print(result_message)
    return 1, result_message


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Error: Incorrect number of arguments. Expected {3}, got {len(sys.argv) - 1}.")
        print("Usage: python3 decrypt_result.py <secret_password> <shared_password> <dir> <output_dir>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
