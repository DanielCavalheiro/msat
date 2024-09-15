import base64
import json
import os
import sys
import argparse


from components.detector import Detector
from utils.token_utils import token_decoder, result_decoder, ResultToken
from tests.old_detector import OldDetector

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
    file_path = crypto_stuff.decrypt_gcm(
        token.file_path, secret_password)
    if token.arguments is not None:
        scope_name = crypto_stuff.decrypt_sse(
            base64.b64decode(token.scope_name), secret_password)
        arguments = []
        for arg in token.arguments:
            arguments.append(decrypt_token(arg, secret_password))
        return ResultToken(token_type, line_num, position, file_path, scope_name, arguments)
    elif token.scope_name is not None:
        scope_name = crypto_stuff.decrypt_sse(
            base64.b64decode(token.scope_name), secret_password)
        return ResultToken(token_type, line_num, position, file_path, scope_name)

    return ResultToken(token_type, line_num, position, file_path)


parser = argparse.ArgumentParser(description="Run all components of the tool in sequence.", epilog="NOTE: If no encryption is used then secret/shared password is not needed and will be ignored.")
parser.add_argument("--project_dir", "-p", help="The directory of the project to be analyzed.", required=True)
parser.add_argument("--no-encryption", "-ne", help="Disable encryption.", dest='encrypt', action="store_false", default=True, required=False)
parser.add_argument("--vuln_type", "-v", help="The type of vulnerability to detect, either XSS or SQLI.", required=True, choices=["xss", "sqli"])
parser.add_argument("--secret_password", "-sep", help="The secret password to encrypt critical data.", required=False)
parser.add_argument("--shared_password", "-shp", help="The shared password to encrypt data used in detection.", required=False)

args = parser.parse_args()

if not os.path.exists(args.project_dir):
    print(f"{args.project_dir} does not exist")
    sys.exit(1)

secret_password = bytes("default", "utf-8")
shared_password = bytes("default", "utf-8")
if args.encrypt:
    if not args.secret_password or not args.shared_password:
        parser.error("--secret_password (-sep) and --shared_password (-shp) are required when --encrypt (-e) is set to True.")
    secret_password = crypto_stuff.generate_key(args.secret_password)
    shared_password = crypto_stuff.generate_key(args.shared_password)

data_structure = {}
lexer = Abstractor()

try:
    for root, dirs, files in os.walk(args.project_dir):
        for file in files:
            if file.endswith('.php'):
                php_file = os.path.join(root, file)
                with open(php_file, "r", encoding="latin-1") as data:
                    scope = os.path.basename(php_file)
                    lexer.file_name = scope
                    lexer.input(data.read())
                    lexer.lineno = 1
                    correlator = Correlator(lexer, data_structure, 0, 0, scope, {}, php_file)
                    correlator.correlate()

    encryptor = Encryptor(args.encrypt)
    encryptor.encrypt_data_structure(
        data_structure, secret_password, shared_password,)

    with open("client_side_output", "r", encoding="utf-8") as f:
        detector = None

        if args.encrypt:
            decrypted_data = crypto_stuff.decrypt_gcm(f.read(), shared_password)
            encrypted_ds = json.loads(decrypted_data, object_hook=token_decoder)
            detector = Detector(encrypted_ds, shared_password)
        else:
            not_encrypted_ds = json.load(f, object_hook=token_decoder)
            detector = OldDetector(not_encrypted_ds, shared_password, args.encrypt)

        detector.set_vuln_type(args.vuln_type.upper())
        vulnerable_paths = detector.detect_vulnerability()
        encryptor.encrypt_result(vulnerable_paths, shared_password)

    with open("auditor_side_output", "r", encoding="utf-8") as f:
        if args.encrypt:
            decrypted_data = crypto_stuff.decrypt_gcm(f.read(), shared_password)
        else:
            decrypted_data = f.read()

        vulnerable_paths = json.loads(decrypted_data, object_hook=result_decoder)
        special_tokens = crypto_stuff.populate_special_tokens(shared_password)
        path_counter = 0
        for path in vulnerable_paths:
            path_counter += 1
            print(f"\nVulnerable path {path_counter}:")
            for token in path:
                if args.encrypt:
                    print("\t" + str(decrypt_token(token, secret_password)))
                else:
                    print("\t" + str(token))

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

print("All in one completed successfully!")
print("Vulnerable paths were printed above if any.")
os.remove("client_side_output")
os.remove("auditor_side_output")
