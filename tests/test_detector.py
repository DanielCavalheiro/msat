from utils.token_utils import ResultToken, token_decoder, result_decoder
import utils.crypto_stuff as crypto_stuff
from components.detector import Detector
from components.encryptor import Encryptor
from components.abstractor import Abstractor
from components.correlator import Correlator
from tests.old_detector import OldDetector
import base64
import json
import os

ENCRYPT_FLAG = True
SECRET_PASSWORD = crypto_stuff.generate_key("secret_password")
SHARED_PASSWORD = crypto_stuff.generate_key("shared_password")
DETECTING = "XSS"
DIR = "/home/dani/tese/hollingworth_app/testing_dir"


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


data_structure = {}
lexer = Abstractor()
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

encryptor = Encryptor(ENCRYPT_FLAG)
encryptor.encrypt_data_structure(
    correlator.data_structure, SECRET_PASSWORD, SHARED_PASSWORD)

vulnerable_paths = []

with open("client_side_output", "r", encoding="utf-8") as f:
    detector = None
    if ENCRYPT_FLAG:
        decrypted_data = crypto_stuff.decrypt_gcm(f.read(), SHARED_PASSWORD)
        encrypted_ds = json.loads(decrypted_data, object_hook=token_decoder)
        detector = Detector(encrypted_ds, SHARED_PASSWORD, ENCRYPT_FLAG)
    else:
        not_encrypted_ds = json.loads(f.read(), object_hook=token_decoder)
        detector = OldDetector(not_encrypted_ds, SHARED_PASSWORD, ENCRYPT_FLAG)

    detector.set_vuln_type(DETECTING)
    vulnerable_paths = detector.detect_vulnerability()

encryptor.encrypt_result(vulnerable_paths, SHARED_PASSWORD)

with open("auditor_side_output", "r", encoding="utf-8") as f:
    if ENCRYPT_FLAG:
        decrypted_data = crypto_stuff.decrypt_gcm(f.read(), SHARED_PASSWORD)
    else:
        decrypted_data = f.read()
    vulnerable_paths = json.loads(decrypted_data, object_hook=result_decoder)
    special_tokens = crypto_stuff.populate_special_tokens(SHARED_PASSWORD)
    path_counter = 0
    for path in vulnerable_paths:
        path_counter += 1
        print(f"\nVulnerable path {path_counter}:")
        for token in path:
            if ENCRYPT_FLAG:
                print("\t" + str(decrypt_token(token, SECRET_PASSWORD)))
            else:
                print("\t" + str(token))
