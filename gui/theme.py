import logging

def apply_theme(app, theme):
    """
    Applies the specified theme ('dark' or 'light') to the given app (QMainWindow or QWidget).
    """
    if theme == 'dark':
        app.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #f0f0f0;
            }
            QPushButton {
                background-color: #3b3b3b;
                color: #ffffff;
                border: 1px solid #505050;
                border-radius: 8px;
                padding: 10px 15px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #505050;
            }
            QPushButton:pressed {
                background-color: #606060;
            }
            QTextEdit, QLineEdit, QComboBox {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #4c4c4c;
                padding: 8px;
                border-radius: 6px;
            }
            QTextEdit {
                background-color: #2e2e2e;
                padding: 10px;
            }
            QComboBox::drop-down {
                background-color: #3b3b3b;
                border-left: 1px solid #505050;
            }
            QComboBox QAbstractItemView {
                background-color: #3b3b3b;
                color: #ffffff;
                border: 1px solid #505050;
            }
            QDialog {
                background-color: #2b2b2b;
                color: #f0f0f0;
                border-radius: 10px;
            }
            QLabel {
                font-weight: bold;
                color: #e0e0e0;
                font-size: 14px;
            }
        """)
        app.toggle_theme_button.setText("Switch to Light Mode")
        app.current_theme = 'dark'

    else:
        app.setStyleSheet("""
            QWidget {
                background-color: #f4f4f4;
                color: #2e2e2e;
            }
            QPushButton {
                background-color: #e6e6e6;
                color: #2e2e2e;
                border: 1px solid #bdbdbd;
                border-radius: 8px;
                padding: 10px 15px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #d4d4d4;
            }
            QPushButton:pressed {
                background-color: #c4c4c4;
            }
            QTextEdit, QLineEdit, QComboBox {
                background-color: #ffffff;
                color: #2e2e2e;
                border: 1px solid #d1d1d1;
                padding: 8px;
                border-radius: 6px;
            }
            QTextEdit {
                background-color: #fafafa;
                padding: 10px;
            }
            QComboBox::drop-down {
                background-color: #e6e6e6;
                border-left: 1px solid #bdbdbd;
            }
            QComboBox QAbstractItemView {
                background-color: #ffffff;
                color: #2e2e2e;
                border: 1px solid #bdbdbd;
            }
            QDialog {
                background-color: #f4f4f4;
                color: #2e2e2e;
                border-radius: 10px;
            }
            QLabel {
                font-weight: bold;
                color: #2e2e2e;
                font-size: 14px;
            }
        """)
        app.toggle_theme_button.setText("Switch to Dark Mode")
        app.current_theme = 'light'


def toggle_theme(app):
    """
    Toggles between light and dark themes.
    """
    new_theme = 'dark' if app.current_theme == 'light' else 'light'
    logging.info(f"Switching to {new_theme} theme.")
    apply_theme(app, new_theme)

def clear_logs(app):
    app.log_viewer.clear()
   
    