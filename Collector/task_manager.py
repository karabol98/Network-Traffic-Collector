import asyncio
import logging
import threading
from queue import Queue, Empty
from typing import Dict

logger = logging.getLogger('uvicorn.error')

class TaskManager:
    def __init__(self, num_workers=4):
        self.queue = Queue()
        self.workers: Dict[str, threading.Thread] = {}
        self.running = True
        self.num_workers = num_workers

    def workerid(self, index: int):
        return(f"worker_{index}")

    def worker(self, worker_id: str):
        while self.running:
            try:
                # Get task from queue with timeout
                task = self.queue.get(timeout=1.0)
                logger.info(f"Worker {worker_id} processing task: {task}")
                # Process task here
                if asyncio.iscoroutinefunction(task):
                    asyncio.run(task())
                else:
                    if asyncio.iscoroutine(task):
                        asyncio.run(task)
                    else:
                        task()

                self.queue.task_done()
            except Empty:
                continue
            except Exception as e:
                logger.exception(f"Error in worker {worker_id}")
        logger.info(f"Worker {worker_id} shutting down.")

    def start_workers(self):
        for i in range(self.num_workers):
            worker_id = self.workerid(i)
            thread = threading.Thread(
                target=self.worker,
                args=(worker_id,),
                daemon=True
            )
            thread.start()
            logger.info(f"Started worker {worker_id}.")
            self.workers[worker_id] = thread

    def add_task(self, task):
        self.queue.put(task)

    def shutdown(self):
        self.running = False
        # Wait for all workers to complete
        for worker in self.workers.values():
            worker.join(timeout=1.0)
