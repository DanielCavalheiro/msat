import base64
import json
import os
import sys

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from components.detector import Detector
from utils.token_utils import token_decoder, result_decoder, ResultToken


from components.correlator import Correlator
from components.abstractor import Abstractor
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff

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


if len(sys.argv) != 6:
    print(f"Error: Incorrect number of arguments. Expected {5}, got {len(sys.argv) - 1}.")
    print("Usage: python3 all_in_one.py <secret_password> <shared_password> <dir> <output_dir> <vulnerability_to_detect>")
    sys.exit(1)

SECRET_PASSWORD = crypto_stuff.generate_key(sys.argv[1])
SHARED_PASSWORD = crypto_stuff.generate_key(sys.argv[2])

DIR = sys.argv[3]
if not os.path.exists(DIR):
    print(f"{DIR} does not exist")
    sys.exit(1)

OUTPUT_DIR = sys.argv[4]
if not os.path.exists(OUTPUT_DIR):
    print(f"{OUTPUT_DIR} does not exist")
    sys.exit(1)

VULNERABILITY_TO_DETECT = sys.argv[5].upper()

data_structure = {}
lexer = Abstractor()

try:
    for root, dirs, files in os.walk(DIR):
        for file in files:
            if file.endswith('.php'):
                php_file = os.path.join(root, file)
                with open(php_file, "r", encoding="utf-8") as data:
                    scope = os.path.basename(php_file)
                    lexer.file_name = scope
                    lexer.input(data.read())
                    lexer.lineno = 1

                    correlator = Correlator(lexer, data_structure, 0, 0, scope, {})
                    correlator.correlate()

    encryptor = Encryptor()
    encryptor.encrypt_data_structure(
        data_structure, SECRET_PASSWORD, SHARED_PASSWORD, OUTPUT_DIR)

    with open(OUTPUT_DIR+"/client_side_output", "r", encoding="utf-8") as f:
        detector = None
        decrypted_data = crypto_stuff.decrypt_gcm(f.read(), SHARED_PASSWORD)
        encrypted_ds = json.loads(decrypted_data, object_hook=token_decoder)
        detector = Detector(encrypted_ds, SHARED_PASSWORD)

        if VULNERABILITY_TO_DETECT not in ("XSS", "SQLI"):
            sys.exit("Invalid vulnerability type. Please choose between XSS and SQLI.")
        detector.set_vuln_type(VULNERABILITY_TO_DETECT)
        vulnerable_paths = detector.detect_vulnerability()
        encryptor = Encryptor()
        encryptor.encrypt_result(vulnerable_paths, SHARED_PASSWORD, OUTPUT_DIR)

    with open(OUTPUT_DIR+"/auditor_side_output", "r", encoding="utf-8") as f:
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

print("All in one completed successfully!")
print("Vulnerable paths were printed above if any.")

