import sys
from PyQt5.QtWidgets import QApplication
from gui.layout import IAMManagerApp

def main():
    # Create a QApplication instance (PyQt5 application object)
    app = QApplication(sys.argv)
    
    # Create the main window instance of IAMManagerApp
    window = IAMManagerApp()
    
    # Show the main window
    window.show()
    
    # Execute the application's event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
