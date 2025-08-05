import logging
import logging.handlers
import tkinter as tk
import traceback
# logging and logging.handlers are imported for handling and formatting log messages.

"""
__init__ Method:
Initializes the LogHandler class.
The app parameter represents the main application or a Tkinter window that contains the log viewer widget.
The super().__init__() call ensures that the base class (logging.Handler) is properly initialized.
"""

"""
def emit(self,record)
Purpose: The emit method is overridden from logging.Handler and is responsible for formatting the log record and passing it to the log viewer in the GUI.

Steps:

self.format(record): Formats the log message according to the handler's formatter.
The comment suggests ensuring thread-safe updates to the log viewer, which is essential because Tkinter GUI operations need to happen in the main thread.
The except block catches and logs any errors that occur during the process.
"""


"""
def update_log_viewer()
Purpose: This method updates the Tkinter Text widget (referred to as log_viewer) with new log messages.
Steps:
self.app.log_viewer.configure(state='normal'): Enables editing in the Text widget so that new text can be inserted.
self.app.log_viewer.insert(tk.END, message + '\n'): Inserts the new log message at the end of the widget.
self.app.log_viewer.configure(state='disabled'): Disables editing again to prevent user input.
self.app.log_viewer.yview(tk.END): Scrolls the view to the end to show the most recent log message.
Error Handling: If an error occurs during these operations, it will be logged.
"""

"""
Summary
This code sets up a custom logging handler for a Tkinter application. It formats log messages and displays them in a Tkinter Text widget. The key addition is ensuring that GUI updates occur in a thread-safe manner using app.after(). This ensures that logs are displayed correctly even when generated from different threads.
"""

class LogHandler(logging.Handler):
    """
    Custom log handler to display log messages in a Tkinter Text widget (log_viewer).
    Ensures GUI updates happen in the main thread using root.after().
    """

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    def emit(self, record):
        try:
            msg = self.format(record)
            if hasattr(self.app, 'log_viewer'):
                self.app.after(0, self.update_log_viewer, msg)
            else:
                print("Error: 'log_viewer' not found in app.")
        except Exception as e:
            self.handle_exception(e)

    def update_log_viewer(self, message):
        try:
            if hasattr(self.app, 'log_viewer'):
                self.app.log_viewer.configure(state='normal')
                self.app.log_viewer.insert(tk.END, message + '\n')
                self.app.log_viewer.configure(state='disabled')
                self.app.log_viewer.yview(tk.END)
            else:
                print("Error: 'log_viewer' not found in app.")
        except Exception as e:
            self.handle_exception(e)

    def handle_exception(self, exception):
        error_msg = ''.join(traceback.format_exception(type(exception), exception, exception.__traceback__))
        print(f'[LogHandler Error] {error_msg}')


class LogHandler:
    def __init__(self, text_edit):
        self.text_edit = text_edit

    def update_log_viewer(self, message):
        self.text_edit.append(message)
        self.text_edit.ensureCursorVisible()
        