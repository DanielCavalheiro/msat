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

            # while True:
            #     token = lexer.token()
            #     if not token:
            #         break
            #     print(token)


if __name__ == "__main__":
    FILE = "/home/dani/tese/hollingworth_app/xss1.php"
    tokenize(FILE)
