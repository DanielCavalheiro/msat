"""Module for the Encryptor component"""

import json
from utils.token_utils import AbsToken, FuncCallToken, TokenEncoder
import utils.crypto_stuff as crypto_stuff

SPECIAL_TOKENS = ("INPUT", "XSS_SENS", "XSS_SANF",
                  "SQLI_SENS", "SQLI_SANF", "FUNC_CALL",
                  "RETURN", "ARGS")


class Encryptor:
    """Encryptor component to encrypt data strcutur."""

    def __init__(self, encrypt_flag):
        self.encrypt_flag = encrypt_flag  # Flag to encrypt or not

    def encrypt_data_structure(self, data_structure: dict, secret_password, shared_password):
        """Encrypt the data structure with the given password."""

        if not self.encrypt_flag:
            with open("../encrypted_ds", "w", encoding="utf-8") as f:
                json.dump(data_structure, f, cls=TokenEncoder, indent=4)
            return

        encrypted_ds = {}  # Encrypted data structure
        encrypted_data = None
        for scope, values in data_structure.items():
            enc_scope = crypto_stuff.encrypt_sse(scope, secret_password)
            enc_scope = crypto_stuff.hmac_it(enc_scope, shared_password)
            encrypted_ds[enc_scope] = {}
            for key, vs in values.items():
                if key in SPECIAL_TOKENS:
                    enc_key = crypto_stuff.hmac_it(key, shared_password)
                    # HMAC again so no trace can be seen in the resulting data
                    enc_key = crypto_stuff.hmac_it(enc_key, shared_password)
                else:
                    enc_key = crypto_stuff.encrypt_sse(key, secret_password)
                    # HMAC again so no trace can be seen in the resulting data
                    enc_key = crypto_stuff.hmac_it(enc_key, shared_password)
                enc_assignors = []
                for value in vs:
                    enc_assignors.append(
                        self.__encrypt_token(value, secret_password, shared_password))
                encrypted_ds[enc_scope][enc_key] = enc_assignors

                encrypted_ds_json = json.dumps(encrypted_ds, cls=TokenEncoder, indent=4)
                encrypted_data = crypto_stuff.encrypt_gcm(encrypted_ds_json, shared_password)

        with open("../encrypted_ds", "w", encoding="utf-8") as f:
            json.dump(encrypted_data, f, cls=TokenEncoder, indent=4)

    def __encrypt_token(self, token, secret_password, shared_password):
        """Encrypt the token with the given password."""

        line_num = crypto_stuff.encrypt_sse(
            str(token.line_num), secret_password)
        position = crypto_stuff.encrypt_ope(
            token.token_pos, secret_password)
        depth = crypto_stuff.encrypt_ope(
            token.depth, secret_password)
        order = crypto_stuff.encrypt_ope(
            token.order, secret_password)
        flow_type = crypto_stuff.encrypt_ope(
            token.flow_type, secret_password)
        scope = crypto_stuff.encrypt_sse(
            token.scope, secret_password)

        if isinstance(token, FuncCallToken):
            token_type = crypto_stuff.hmac_it(
                token.token_type, shared_password)

            func_name = crypto_stuff.encrypt_sse(
                token.func_name, secret_password)

            enc_args = []
            for arg in token.arguments:
                enc_args.append(self.__encrypt_token(
                    arg, secret_password, shared_password))

            return FuncCallToken(token_type, line_num, position, depth, order, flow_type, scope, func_name, enc_args)

        else:  # isinstance(token, AbsToken)
            if token.token_type in SPECIAL_TOKENS:
                token_type = crypto_stuff.hmac_it(
                    token.token_type, shared_password)
            else:
                token_type = crypto_stuff.encrypt_sse(
                    token.token_type, secret_password)

            return AbsToken(token_type, line_num, position, depth, order, flow_type, scope)
