from .parsers import OneParser, AnotherParser

def main():
    print("Welcome!")
    url1 = "https://someurl.com/"
    url2 = "https://anourl.com/"

    parser1 = OneParser()
    parser2 = AnotherParser()
    # parse into pydantic model
    # save to database
    # print something


if __name__ == '__main__':
    main()
