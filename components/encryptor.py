"""Module for the Encryptor component"""

import json
import yaml
from utils.token_utils import AbsToken, EncTokenEncoder
from utils.token_utils import EncToken
import utils.crypto_stuff as crypto_stuff


class Encryptor:
    """Encryptor component to encrypt data strcutur."""

    def __init__(self, encrypt_flag):
        self.encrypt_flag = encrypt_flag  # Flag to encrypt or not

    def encrypt_data_structure(self, data_structure: dict, secret_password, shared_password):
        """Encrypt the data structure with the given password."""
        encrypted_ds = {}  # Encrypted data structure
        for key in data_structure:
            if key in ("INPUT", "XSS_SENS", "XSS_SANF", "SQLI_SENS", "SQLI_SANF"):
                enc_key = crypto_stuff.hmac_it(key, shared_password)
            else:
                enc_key = crypto_stuff.encrypt_sse(key, secret_password)
            values = data_structure[key]
            enc_assignors = []
            for value in values:
                enc_assignors.append(
                    self.__encrypt_token(value, secret_password, shared_password))
            encrypted_ds[enc_key] = enc_assignors

        if self.encrypt_flag:
            with open("encrypted_ds", "w", encoding="utf-8") as f:
                json.dump(encrypted_ds, f, cls=EncTokenEncoder, indent=4)
        else:
            with open("encrypted_ds", "w", encoding="utf-8") as f:
                json.dump(data_structure, f, cls=EncTokenEncoder, indent=4)

    def __encrypt_token(self, token: AbsToken, secret_password, shared_password):
        """Encrypt the token with the given password."""
        if token.token_type in ("INPUT", "XSS_SENS", "XSS_SANF", "SQLI_SENS", "SQLI_SANF"):
            token_type = crypto_stuff.hmac_it(
                token.token_type, shared_password)
        else:
            token_type = crypto_stuff.encrypt_sse(
                token.token_type, secret_password)

        line_num = crypto_stuff.encrypt_sse(
            str(token.line_num), secret_password)
        position = crypto_stuff.encrypt_ope(token.token_pos, secret_password)
        depth = crypto_stuff.encrypt_ope(token.depth, secret_password)
        order = crypto_stuff.encrypt_ope(token.order, secret_password)
        flow_type = crypto_stuff.encrypt_ope(token.flow_type, secret_password)
        return EncToken(token_type, line_num, position, depth, order, flow_type)
