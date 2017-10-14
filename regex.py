from entropy import shannon_entropy
import re


class RegexFactory(object):
    @staticmethod
    def get_base64():
        return re.compile('(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

    @staticmethod
    def get_domain():
        return re.compile(r'[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})+')

    @staticmethod
    def get_ip():
        return re.compile(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})')

    @staticmethod
    def get_strings(min_char_count):
        return re.compile(('([\w/]{%s}[\w/]*)' % min_char_count).encode())


def entropy(data):
    return shannon_entropy(data)


def null_terminate_and_decode_utf8(str):
    return str.decode('utf-8', 'ignore').split('\x00', 1)[0]


def strings(data, min_char_count=4):
    for match in RegexFactory.get_strings(min_char_count).finditer(data):
        yield match.group(0)
