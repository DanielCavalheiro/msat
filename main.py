""" Main file for the project. """


import base64
import json
from components.abstractor import Abstractor
from components.correlator import Correlator
from components.detector import Detector
from components.encryptor import Encryptor
import utils.crypto_stuff as crypto_stuff
from utils.token_utils import AbsToken, EncToken, enc_token_decoder


def tokenize(file):
    try:
        data = open(file, "r", encoding="utf-8")
    except FileNotFoundError:
        print("File not found")
    else:
        with data:

            encrypt_flag = False

            # -------------------------------- Client side ------------------------------- #

            lexer = Abstractor()
            lexer.input(data.read())

            correlator = Correlator(lexer, {}, 0, 0)
            correlator.correlate()

            encryptor = Encryptor(encrypt_flag)

            # Password known only by the client
            secret_password = crypto_stuff.generate_key("secret_password")

            # Password known by the client and the auditor
            shared_password = crypto_stuff.generate_key("shared_password")

            encryptor.encrypt_data_structure(
                correlator.data_structure, secret_password, shared_password)

            # ------------------------------- Auditor Side ------------------------------- #

            encrypted_ds = {}
            with open("encrypted_ds", "r", encoding="utf-8") as f:
                encrypted_ds = json.loads(
                    f.read(), object_hook=enc_token_decoder)

            detector = Detector(encrypted_ds, shared_password, encrypt_flag)
            detector.set_vuln_type("SQLI")
            vulnerable_paths = detector.detect_vulnerability()

            # ------------------------------- Decode Result (Client Side) ------------------------------ #

            special_tokens = crypto_stuff.populate_special_tokens(
                shared_password)  # TODO change location

            def decrypt_token(token: EncToken, secret_password):
                """Decrypts an encrypted token."""
                if token.token_type == special_tokens["INPUT"]:
                    token_type = token.token_type
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
                return AbsToken(token_type, line_num, position, depth, order, flow_type)

            path_counter = 0
            for path in vulnerable_paths:
                path_counter += 1
                print(f"\nVulnerable path {path_counter}:")
                for token in path:
                    if (encrypt_flag):
                        print(
                            "\t" + str(decrypt_token(token, secret_password)))
                    else:
                        print("\t" + str(token))


if __name__ == "__main__":
    FILE = "/home/dani/tese/hollingworth_app/xss4.php"
    tokenize(FILE)
