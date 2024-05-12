"""Module for the Encryptor component"""

from utils.token_utils import AbsToken
from utils.token_utils import EncToken
import utils.crypto_stuff as crypto_stuff
import base64


class Encryptor:
    """Encryptor component to encrypt data strcutur."""

    def __init__(self):
        pass

    def encrypt_data_structure(self, data_structure: dict, password):
        """Encrypt the data structure with the given password."""
        encrypted_ds = {}  # Encrypted data structure
        for key in data_structure:
            encrypted_key = base64.b64encode(base64.b64encode(
                crypto_stuff.encrypt_sse(key, password))).decode("utf-8")
            values = data_structure[key]
            enc_assignors = []
            for value in values:
                enc_assignors.append(self.__encrypt_token(value, password))
            encrypted_ds[encrypted_key] = enc_assignors
        return encrypted_ds

    def encrypt_knowledge_source(self, knowledge_source, password):
        """Encrypt the knowledge source with the given password."""

    def __encrypt_token(self, token: AbsToken, password):
        """Encrypt the token with the given password."""
        token_type = base64.b64encode(base64.b64encode(
            crypto_stuff.encrypt_sse(token.token_type, password))).decode("utf-8")
        line_num = base64.b64encode(base64.b64encode(
            crypto_stuff.encrypt_sse(str(token.line_num), password))).decode("utf-8")
        position = crypto_stuff.encrypt_ope(token.token_pos, password)
        depth = crypto_stuff.encrypt_ope(token.depth, password)
        order = crypto_stuff.encrypt_ope(token.order, password)
        flow_type = crypto_stuff.encrypt_ope(token.flow_type, password)
        return EncToken(token_type, line_num, position, depth, order, flow_type)
