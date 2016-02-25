
import hashlib


__author__ = 'Khiem Doan'


class File:

    _file_path = None

    def __init__(self, file_path):
        self._file_path = file_path

    def read(self):
        file = open(self._file_path, "rb")
        content = file.read()
        file.close()
        return content

    def write(self, content):
        file = open(self._file_path, "wb+")
        file.write(content)
        file.close()

    def get_sha1(self):
        sha = hashlib.sha1()
        sha.update(self.read())
        return sha.hexdigest()

    def get_sha256(self):
        sha = hashlib.sha256()
        sha.update(self.read())
        return sha.hexdigest()
