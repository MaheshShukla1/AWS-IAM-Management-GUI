import logging
from gui.layout import Worker  # or move Worker too to utils

def perform_task(app, task_function):
    if hasattr(app, 'worker') and app.worker.isRunning():
        logging.info("Stopping the previous task before starting a new one.")
        app.worker.terminate()

    logging.info("Starting a new background task.")
    app.worker = Worker(task_function)
    app.worker.result.connect(app.log_handler.update_log_viewer)
    app.worker.error.connect(app.log_handler.update_log_viewer)
    app.worker.start()
