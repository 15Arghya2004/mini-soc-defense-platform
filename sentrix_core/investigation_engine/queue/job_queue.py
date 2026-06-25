import queue as stdlib_queue

class JobQueue:
    def __init__(self):
        self.q = stdlib_queue.Queue()

    def put(self, task: dict):
        self.q.put(task)

    def get(self) -> dict:
        return self.q.get()

    def task_done(self):
        self.q.task_done()
