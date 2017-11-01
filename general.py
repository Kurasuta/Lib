import subprocess
import socket
import json
import os
import errno
from datetime import datetime


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()

        return json.JSONEncoder.default(self, o)


class KurasutaApi(object):
    def __init__(self, base_url):
        self.base_url = base_url

    def get_sha256_url(self, hash_sha256):
        return '%s/sha256/%s' % (self.base_url, hash_sha256)

    def get_task_url(self):
        return '%s/task' % self.base_url

    def get_user_agent(self):
        return 'Kurasuta Worker (%s-%s)' % (KurasutaSystem.get_host(), KurasutaSystem.git_revision())


class KurasutaSystem(object):
    def __init__(self, storage):
        if not storage:
            raise Exception('KURASUTA_STORAGE location "%s" missing' % storage)
        if not storage:
            raise Exception('KURASUTA_STORAGE location "%s" is not a directory' % storage)
        self.storage = storage

    @staticmethod
    def get_host():
        return socket.gethostname()

    @staticmethod
    def git_revision():
        return subprocess.check_output([
            'git', '-C', os.path.dirname(os.path.realpath(__file__)),
            'rev-parse', '--short', 'HEAD'
        ]).strip().decode('utf-8')

    def get_hash_dir(self, hash_sha256):
        return os.path.join(self.storage, hash_sha256[0], hash_sha256[1], hash_sha256[2])

    @staticmethod
    def mkdir_p(path):
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno == errno.EEXIST and os.path.isdir(path):
                pass
            else:
                raise
