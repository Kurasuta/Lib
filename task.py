import random
from .flask import InvalidUsage
from .sample import FrozenClass


class TaskRequest(FrozenClass):
    def __init__(self, task_consumer_id, task_consumer_name, plugins):
        self.task_consumer_id = task_consumer_id  # type: int
        self.task_consumer_name = task_consumer_name  # type: str
        self.plugins = tuple(plugins) if isinstance(plugins, list) else plugins  # type: tuple(str)
        self._freeze()


class TaskResponse(FrozenClass):
    def __init__(self, id, payload):
        self.id = id  # type: int
        self.payload = payload  # type: dict
        self._freeze()

    def to_json(self):
        return {'id': self.id, 'payload': self.payload}


class TaskFactory(object):
    def __init__(self, connection=None):
        self.connection = connection

    def request_from_json(self, d):
        if 'name' not in d:
            raise InvalidUsage('Key "name" missing in request.')
        if 'plugins' not in d:
            raise InvalidUsage('Key "plugins" missing in request.')

        task_consumer_id = 0
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT id FROM task_consumer WHERE (name = %s)', (d['name'],))
            row = cursor.fetchone()
            if not row:
                raise InvalidUsage('Consumer with name "%s" does not exist' % d['name'])
            task_consumer_id = int(row[0])
        return TaskRequest(task_consumer_id, d['name'], d['plugins'])

    @staticmethod
    def response_from_json(d):
        if 'id' not in d:
            raise Exception('Keu "id" missing in response.')
        if 'payload' not in d:
            raise Exception('Keu "payload" missing in response.')

        return TaskResponse(d['id'], d['payload'])

    def random_unassigned(self, task_request):
        """
        :type task_request: TaskRequest
        :return: TaskResponse
        """
        with self.connection.cursor() as cursor:
            cursor.execute(
                'SELECT COUNT(id) FROM task WHERE (assigned_at IS NULL) AND (type IN %s)',
                (task_request.plugins,)
            )
            count = cursor.fetchone()[0]
            if not count:
                return None
            offset = random.randint(0, count - 1)
            cursor.execute(
                'SELECT id, payload FROM task WHERE (assigned_at IS NULL) AND (type IN %s) LIMIT 1 OFFSET %s',
                (task_request.plugins, offset)
            )
            task_row = cursor.fetchone()
            if not task_row:
                return None
            task = TaskResponse(task_row[0], task_row[1])
            cursor.execute(
                'UPDATE task SET assigned_at = now(), consumer_id = %s WHERE (id = %s)',
                (task_request.task_consumer_id, task.id)
            )

            return task

    def mark_as_completed(self, id):
        with self.connection.cursor() as cursor:
            cursor.execute('SELECT consumer_id FROM task WHERE (id = %s)', (id,))
            row = cursor.fetchone()
            if not row:
                raise InvalidUsage('Task with id %s does not exist' % id)
            # consumer_id = row[0] TODO check if consumer_ids match

            cursor.execute('UPDATE task SET completed_at = now() WHERE (id = %s)', (id,))
