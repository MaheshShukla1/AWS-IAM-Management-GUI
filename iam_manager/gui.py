import logging.handlers
import tkinter as tk
from tkinter import messagebox,scrolledtext,simpledialog
import logging
from iam_operation import *

# Gui Application
class IAMManagerApp():
    def __init__(self, root):
        self.root = root
        self.root.title("IAM Manager")

        # Setup up Gui components
        self.setup_gui()

        # Set up loging viewer
        self.log_viewer = scrolledtext.ScrolledText(self.root,height=10,width=80,state='disabled')
        self.log_viewer.grid(row=7,column=0,columnspan=4,pady=10)

        # Configure logging to also output to the text widget
        logging.getLogger().addHandler(self.LogHandler(self))

    class LogHandler(logging.Handler):
            def __init__(self, app):
                super().__init__()
                self.app = app

    def setup_gui(self):
        tk.Label(self.root,text="IAM Manager",font=("Arial",16)).grid(row=0,column=0,columnspan=4,pady=10)

        tk.Button(self.root,text="Create User",command=self.create_user).grid(row=1,column=0,padx=5,pady=5)
        tk.Button(self.root,text="List Users",command=self.list_users).grid(row=1,column=2,padx=5,pady=5)
        tk.Button(self.root,text="Delete User",command=self.delete_user).grid(row=1,column=3,padx=5,pady=5)
        tk.Button(self.root,text="Create Role",command=self.create_role).grid(row=2,column=0,padx=5,pady=5)
        tk.Button(self.root,text="Delete Role",command=self.delete_role).grid(row=2,column=1,padx=5,pady=5)
        tk.Button(self.root,text="List Roles",command=self.list_roles).grid(row=2,column=1,padx=5,pady=5)
        tk.Button(self.root,text="Attach Policy To Role",command=self.attach_role_policy).grid(row=2,column=2,padx=5,pady=5)
        tk.Button(self.root,text="Detach Policy to Role",command=self.detach_role_policy).grid(row=2,column=3,padx=5,pady=5)
        tk.Button(self.root,text="Create Policy",command=self.create_policy).grid(row=3,column=0,padx=5,pady=5)
        tk.Button(self.root,text="List Policies",command=self.list_policy).grid(row=3,column=1,padx=5,pady=5)
        tk.Button(self.root,text="Delete Policy",command=self.delete_policy).grid(row=3,column=2,padx=5,pady=5)
        tk.Button(self.root,text="Create Group",command=self.create_group).grid(row=4,column=0,padx=5,pady=5)
        tk.Button(self.root,text="Delete Group",command=self.delete_group).grid(row=4,column=1,padx=5,pady=5)
        tk.Button(self.root,text="Exit",command=self.root.quit).grid(row=4,column=2,columnspan=2,padx=5,pady=5)

        