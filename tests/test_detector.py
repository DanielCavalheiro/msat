import base64
import json
import sys
import os

sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from tests.old_detector import OldDetector
from components.correlator import Correlator
from components.abstractor import Abstractor
from components.encryptor import Encryptor
from components.detector import Detector
import utils.crypto_stuff as crypto_stuff
from utils.token_utils import AbsToken, token_decoder

ENCRYPT_FLAG = False
SECRET_PASSWORD = crypto_stuff.generate_key("secret_password")
SHARED_PASSWORD = crypto_stuff.generate_key("shared_password")
DETECTING = "SQLI"
DIR = "/home/dani/tese/hollingworth_app/testing_dir"

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

                correlator = Correlator(lexer, data_structure, 0, 0, scope, {}, 0)
                correlator.correlate()

encryptor = Encryptor(ENCRYPT_FLAG)
encryptor.encrypt_data_structure(correlator.data_structure, SECRET_PASSWORD, SHARED_PASSWORD)

with open("../encrypted_ds", "r", encoding="utf-8") as f:

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
    special_tokens = crypto_stuff.populate_special_tokens(SHARED_PASSWORD)  # TODO change location


def decrypt_token(token, secret_password):
    """Decrypts an encrypted token."""
    if token.token_type == special_tokens["INPUT"]:
        token_type = "INPUT"
    elif token.token_type == special_tokens["FUNC_CALL"]:
        token_type = "FUNC_CALL"
    else:
        token_type = crypto_stuff.decrypt_sse(base64.b64decode(
            base64.b64decode(token.token_type)), secret_password)
    line_num = crypto_stuff.decrypt_sse(base64.b64decode(
        base64.b64decode(token.line_num)), secret_password)
    position = crypto_stuff.decrypt_ope(
        token.token_pos, secret_password)
    depth = crypto_stuff.decrypt_ope(
        token.depth, secret_password)
    order = crypto_stuff.decrypt_ope(
        token.order, secret_password)
    flow_type = crypto_stuff.decrypt_ope(
        token.flow_type, secret_password)
    scope = crypto_stuff.decrypt_sse(base64.b64decode(
        base64.b64decode(token.scope)), secret_password)
    return AbsToken(token_type, line_num, position, depth, order, flow_type, scope)

path_counter = 0
for path in vulnerable_paths:
    path_counter += 1
    print(f"\nVulnerable path {path_counter}:")
    for token in path:
        if ENCRYPT_FLAG:
            print("\t" + str(decrypt_token(token, SECRET_PASSWORD)))
        else:
            print("\t" + str(token))