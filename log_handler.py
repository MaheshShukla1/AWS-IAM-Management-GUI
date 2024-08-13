import logging
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
    def __init__(self, root):
        super().__init__()
        self.root = root

    def emit(self, record):
        try:
            msg = self.format(record)
            # Ensure self.root is a Tkinter root or Toplevel window
            if hasattr(self.root, 'log_viewer'):
                self.root.after(0, self.update_log_viewer, msg)
            else:
                print("Error: 'log_viewer' attribute not found in root.")
        except Exception as e:
            # Avoid logging errors here to prevent recursion
            self.handle_exception(e)

    def update_log_viewer(self, message):
        try:
            if hasattr(self.root, 'log_viewer'):
                # Update the log_viewer widget
                self.root.log_viewer.configure(state='normal')  # Allow editing
                self.root.log_viewer.insert(tk.END, message + '\n')  # Insert the message
                self.root.log_viewer.configure(state='disabled')  # Disable editing
                self.root.log_viewer.yview(tk.END)  # Scroll to the end
            else:
                print("Error: 'log_viewer' attribute not found in root.")
        except Exception as e:
            # Handle errors in updating log viewer, avoiding recursion
            self.handle_exception(e)

    def handle_exception(self, exception):
        # Print the error message to the console to avoid recursion
        error_msg = ''.join(traceback.format_exception(type(exception), exception, exception.__traceback__))
        print(f'Error handling log message: {error_msg}')