import abc


class ParserBase(abc.ABC):

    @abc.abstractmethod
    def get_url(self, url: str = None):
        pass

    @abc.abstractmethod
    def parse(self):
        pass


class OneParser(ParserBase):

    def get_url(self, url: str = None):
        pass

    def parse(self):
        pass


class AnotherParser(ParserBase):

    def get_url(self, url: str = None):
        pass

    def parse(self):
        pass
