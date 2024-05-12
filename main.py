""" Main file for the project. """

import json
import base64
from components.abstractor import Abstractor
from components.correlator import Correlator
from components.encryptor import Encryptor
from utils.token_utils import AbsToken, EncTokenEncoder
import utils.crypto_stuff as crypto_stuff


# from ply.lex import lex
# import components.lexer as token_rules


def tokenize(file):
    try:
        data = open(file, "r", encoding="utf-8")
    except FileNotFoundError:
        print("File not found")
    else:
        with data:
            lexer = Abstractor()
            lexer.input(data.read())

            correlator = Correlator(lexer, {}, 0, 0)
            correlator.correlate()

            encryptor = Encryptor()
            password = crypto_stuff.generate_key("password")
            encrypted_ds = encryptor.encrypt_data_structure(
                correlator.data_structure, password)

            for k in correlator.data_structure:
                print(str(k))
                for v in correlator.data_structure[k]:
                    print("\t" + str(v))

            print("\n ------------- Encrypted data structure ------------- \n")

            # iterate over the encrypted_ds and print the values with items() method
            for k, v in encrypted_ds.items():
                print(str(k))
                for value in v:
                    print("\t" + str(value))

            decoded_ds = {}
            for k, v in encrypted_ds.items():
                decoded_key = crypto_stuff.decrypt_sse(
                    base64.b64decode(base64.b64decode(k)), password)
                decoded_values = []
                for value in v:
                    token_type = crypto_stuff.decrypt_sse(
                        base64.b64decode(base64.b64decode(value.token_type)), password)
                    line_num = crypto_stuff.decrypt_sse(
                        base64.b64decode(base64.b64decode(value.line_num)), password)
                    position = crypto_stuff.decrypt_ope(
                        value.token_pos, password)
                    depth = crypto_stuff.decrypt_ope(value.depth, password)
                    order = crypto_stuff.decrypt_ope(value.order, password)
                    flow_type = crypto_stuff.decrypt_ope(
                        value.flow_type, password)
                    decoded_values.append(
                        AbsToken(token_type, line_num, position, depth, order, flow_type))
                decoded_ds[decoded_key] = decoded_values

            print("\n ------------- Decoded data structure ------------- \n")
            for k in decoded_ds:
                print(str(k))
                for v in decoded_ds[k]:
                    print("\t" + str(v))

            # with open("encrypted_ds", "w") as f:
            #    json.dump(encrypted_ds, f, cls=EncTokenEncoder, indent=4)


if __name__ == "__main__":
    FILE = "/home/dani/tese/hollingworth_app/xss2.php"
    tokenize(FILE)
