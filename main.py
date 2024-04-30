from components.abstractor import Abstractor
from components.correlator import Correlator

# from ply.lex import lex
# import components.lexer as token_rules


def tokenize(file):
    try:
        data = open(file, 'r', encoding='utf-8')
    except FileNotFoundError:
        print("File not found")
    else:
        with data:
            lexer = Abstractor()
            lexer.input(data.read())
            data_structure = {}
            correlator = Correlator(lexer, None, None, data_structure, 0, 0, 0)
            correlator.correlate()

            for k in correlator.data_structure:
                print(str(k))
                for v in correlator.data_structure[k]:
                    print("\t" + str(v))

            # while True:
            #     token = lexer.token()
            #     if not token:
            #         break
            #     print(token)


if __name__ == '__main__':
    FILE = "/home/dani/tese/hollingworth_app/xss2.php"
    tokenize(FILE)
