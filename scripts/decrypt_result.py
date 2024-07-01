import base64
import json
import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from utils.token_utils import ResultToken, token_decoder, result_decoder
import utils.crypto_stuff as crypto_stuff

if len(sys.argv) != 4:
    print(f"Error: Incorrect number of arguments. Expected {3}, got {len(sys.argv) - 1}.")
    print("Usage: python3 decrypt_result.py <secret_password> <shared_password> <dir> <output_dir>")
    sys.exit(1)

SECRET_PASSWORD = crypto_stuff.generate_key(sys.argv[1])
SHARED_PASSWORD = crypto_stuff.generate_key(sys.argv[2])
FILE = sys.argv[3]
if not os.path.exists(FILE):
    print(f"{FILE} does not exist")
    sys.exit(1)


def decrypt_token(token, secret_password):
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
            arguments.append(decrypt_token(arg, secret_password))
        return ResultToken(token_type, line_num, position, scope, scope_name, arguments)
    elif token.scope_name is not None:
        scope_name = crypto_stuff.decrypt_sse(
            base64.b64decode(token.scope_name), secret_password)
        return ResultToken(token_type, line_num, position, scope, scope_name)

    return ResultToken(token_type, line_num, position, scope)

try:
    with open(FILE, "r", encoding="utf-8") as f:
        decrypted_data = crypto_stuff.decrypt_gcm(f.read(), SHARED_PASSWORD)
        vulnerable_paths = json.loads(decrypted_data, object_hook=result_decoder)
        special_tokens = crypto_stuff.populate_special_tokens(SHARED_PASSWORD)
        path_counter = 0
        for path in vulnerable_paths:
            path_counter += 1
            print(f"\nVulnerable path {path_counter}:")
            for token in path:
                print("\t" + str(decrypt_token(token, SECRET_PASSWORD)))
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

print("Decryption completed successfully!")
print("Vulnerable paths were printed above if any.")
