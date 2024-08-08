import tkinter as tk
from gui import IAMManagerApp


def main():
    root = tk.Tk()
    app = IAMManagerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()