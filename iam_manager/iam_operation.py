import boto3
from botocore.exceptions import ClientError
from utils import logging
from tkinter import messagebox,scrolledtext,simpledialog


# Setup The IAM Client
iam = boto3.client('iam')

def create_user(self):
    user_name = simpledialog.askstring("Create User","Enter username:")
    if user_name:
        try:
            iam.create_user(UserName=user_name)
            logging.info(f'User {user_name} created successfully.')
            messagebox.showinfo("Success",f'User {user_name} created successfully.')
        except iam.exceptions.EntityAlreadyExistsException:
            logging.error(f'User {user_name} already exists.')
            messagebox.showerror("Error",f'User {user_name} already exists.')
        except ClientError as e:
            logging.error(f'ClientError creating user {user_name}: {e}')
            messagebox.showerror("Error",f'Error Creating user {user_name}: {e}')


