""" Main file for the project. """


from components.abstractor import Abstractor
from components.correlator import Correlator
from components.encryptor import Encryptor
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

            for k, v in correlator.data_structure.items():
                print(k)
                for token in v:
                    print("\t" + str(token))

            encryptor = Encryptor()

            # Password known only by the client
            secret_password = crypto_stuff.generate_key("secret_password")

            # Password known by the client and the auditor
            shared_password = crypto_stuff.generate_key("shared_password")

            encryptor.encrypt_data_structure(
                correlator.data_structure, secret_password, shared_password)

            encryptor.encrypt_knowledge_source(secret_password)


#             with open("encrypted_ds", "r", encoding="utf-8") as f:
#                 data = json.loads(f.read())
#                 print(data)
#                 decoded_ds = {}
#                 for k, v in data.items():
#                     decoded_key = crypto_stuff.decrypt_sse(
#                         base64.b64decode(base64.b64decode(k)), password)
#                     decoded_values = []
#                     for value in v:
#                         token_type = crypto_stuff.decrypt_sse(
#                             base64.b64decode(base64.b64decode(value["token_type"])), password)
#                         line_num = crypto_stuff.decrypt_sse(
#                             base64.b64decode(base64.b64decode(value["line_num"])), password)
#                         position = crypto_stuff.decrypt_ope(
#                             value["token_pos"], password)
#                         depth = crypto_stuff.decrypt_ope(
#                             value["depth"], password)
#                         order = crypto_stuff.decrypt_ope(
#                             value["order"], password)
#                         flow_type = crypto_stuff.decrypt_ope(
#                             value["flow_type"], password)
#                         decoded_values.append(
#                             AbsToken(token_type, line_num, position, depth, order, flow_type))
#                     decoded_ds[decoded_key] = decoded_values
#
#                 print("\n ------------- Decoded data structure ------------- \n")
#                 for k in decoded_ds:
#                     print(str(k))
#                     for v in decoded_ds[k]:
#                         print("\t" + str(v))


if __name__ == "__main__":
    FILE = "/home/dani/tese/hollingworth_app/xss2.php"
    tokenize(FILE)
