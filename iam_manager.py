import threading
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext,ttk,messagebox,simpledialog,Toplevel,StringVar,Radiobutton, Button
import boto3
import logging
import re
import asyncio
from log_handler import LogHandler
from validate_json import validate_json,json
from botocore.exceptions import ClientError

class IAMManagerApp:
    def __init__(self,root):
        self.root = root
        self.root.title("AWS IAM Management GUI")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f0f0")

        # Initialize IAM, STS client
        try:
          self.iam = boto3.client('iam')
          self.sts = boto3.client('sts')
        except Exception as e:
          logging.error(f"Failed to initialize AWS clients: {e}")
          self.iam = None
          self.sts = None

        self.validate_json = validate_json
       

         # Define themes
        self.light_mode = {
            'bg': '#ffffff',
            'fg': '#000000',
            'button_bg': '#007bff',
            'button_fg': '#000000',
            'button_active_bg': '#0056b3',
            'log_bg': '#ffffff',
            'log_fg': '#000000',
            'entry_bg': '#ffffff',
            'entry_fg': '#000000',
            'text_bg': '#ffffff',
            'text_fg': '#000000'
        }

        self.dark_mode = {
            'bg': '#333333',
            'fg': '#ffffff',
            'button_bg': '#555555',
            'button_fg': '#ffffff',
            'button_active_bg': '#777777',
            'log_bg': '#333333',
            'log_fg': '#ffffff',
            'entry_bg': '#555555',
            'entry_fg': '#ffffff',
            'text_bg': '#333333',
            'text_fg': '#ffffff'
        }
         # Set default theme
        self.current_theme = self.light_mode

        # Initialize Dialog State
        self.dialog_active = False

        # Setup Gui Components
        self.setup_gui()

        # # Initialize log viewer
        # self.log_viewer = scrolledtext.ScrolledText(self.root, height=15, width=100, state='disabled',
        #                                             bg='#ffffff', fg='#000000', font=("Arial", 10))
        # self.log_viewer.grid(row=10, column=0, columnspan=4, pady=10, padx=10, sticky="ew")
        # Initialize log viewer
        self.log_viewer = scrolledtext.ScrolledText(self.root, height=15, width=100, state='disabled',
                                            bg='#ffffff', fg='#000000', font=("Arial", 10))
        self.log_viewer.grid(row=10, column=0, columnspan=4, pady=10, padx=10, sticky="nsew")


        self.setup_logging()
          # Apply the initial theme
        self.apply_theme(self.current_theme)
    
    """
    Purpose: This method sets up logging so that all log messages can be displayed in the log_viewer text widget.

    Explanation: logging.getLogger().handlers: Retrieves all handlers currently attached to the root logger.
    isinstance(handler, LogHandler): Checks if a LogHandler is already attached. This prevents adding multiple handlers.
    logging.getLogger().addHandler(LogHandler(self)): Adds the custom LogHandler that sends log messages to the log_viewer.
    """
    def setup_logging(self):
     if not any(isinstance(handler, LogHandler) for handler in logging.getLogger().handlers):
        self.log_handler = LogHandler(self)  # Store reference to LogHandler instance
        logging.getLogger().addHandler(self.log_handler)
    
    def setup_gui(self):
     title_label = tk.Label(self.root, text="AWS IAM Management GUI", font=("Arial", 24, "bold"), bg=self.current_theme['bg'])
     title_label.grid(row=0, column=0, columnspan=4, pady=20, padx=15, sticky="ew")  # Use sticky="ew" to center

     # Center the title label by making the columns expand evenly
     self.root.grid_columnconfigure(0, weight=1)
     self.root.grid_columnconfigure(1, weight=1)
     self.root.grid_columnconfigure(2, weight=1)
     self.root.grid_columnconfigure(3, weight=1)

     button_style = ttk.Style()
     button_style.configure("TButton",
                           padding=6,
                           relief="flat",
                           background=self.current_theme['button_bg'],
                           foreground=self.current_theme['button_fg'],
                           font=("Arial", 10, "bold"),
                           borderwidth=1)
     button_style.map("TButton",
                     background=[("active", self.current_theme['button_active_bg'])],
                     foreground=[("pressed", self.current_theme['button_fg']),
                                 ("active", self.current_theme['button_fg'])])

     # Define a grid layout with 4 columns and some space between buttons
     button_params = {'padx': 15, 'pady': 10}

     ttk.Button(self.root, text="Create User", command=self.create_user).grid(row=1, column=0, padx=10, pady=10)
     ttk.Button(self.root, text="List Users", command=self.list_users).grid(row=1, column=1, padx=10, pady=10)
     ttk.Button(self.root, text="Delete User", command=self.delete_user).grid(row=1, column=2, padx=10, pady=10)
     ttk.Button(self.root, text="Create Role", command=self.create_role).grid(row=1, column=3, padx=10, pady=10)
     ttk.Button(self.root, text="Delete Role", command=self.delete_role).grid(row=2, column=0, padx=10, pady=10)
     ttk.Button(self.root, text="List Roles", command=self.list_roles).grid(row=2, column=1, padx=10, pady=10)
     ttk.Button(self.root, text="Attach Policy to Role", command=self.attach_role_policy).grid(row=2, column=2, padx=10, pady=10)
     ttk.Button(self.root, text="Detach Policy from Role", command=self.detach_role_policy).grid(row=2, column=3, padx=10, pady=10)
     ttk.Button(self.root, text="Create Policy", command=self.create_policy).grid(row=3, column=0, padx=10, pady=10)
     ttk.Button(self.root, text="List Policies", command=self.list_policies).grid(row=3, column=1, padx=10, pady=10)
     ttk.Button(self.root, text="Delete Policy", command=self.delete_policy).grid(row=3, column=2, padx=10, pady=10)
     ttk.Button(self.root, text="Create Group", command=self.create_group).grid(row=4, column=0, padx=10, pady=10)
     ttk.Button(self.root, text="Delete Group", command=self.delete_group).grid(row=4, column=1, padx=10, pady=10)
     ttk.Button(self.root, text="Clear Logs", command=self.clear_logs).grid(row=4, column=2, padx=10, pady=10)
     ttk.Button(self.root, text="Exit", command=self.root.quit).grid(row=4, column=3, padx=10, pady=10)

     # Add search functionality
     tk.Label(self.root, text="Search User:", bg="#f0f0f0").grid(row=5, column=0, padx=10, pady=10, sticky="e")
     self.search_user_entry = tk.Entry(self.root, font=("Arial", 12))
     self.search_user_entry.grid(row=5, column=1, padx=10, pady=10)
     ttk.Button(self.root, text="Search", command=self.search_user).grid(row=5, column=2, padx=10, pady=10)

     tk.Label(self.root, text="Search Role:", bg="#f0f0f0").grid(row=6, column=0, padx=10, pady=10, sticky="e")
     self.search_role_entry = tk.Entry(self.root, font=("Arial", 12))
     self.search_role_entry.grid(row=6, column=1, padx=10, pady=10)
     ttk.Button(self.root, text="Search", command=self.search_role).grid(row=6, column=2, padx=10, pady=10)

     tk.Label(self.root, text="Search Policy (by Name):", bg="#f0f0f0").grid(row=7, column=0, padx=10, pady=10, sticky="e")
     self.search_policy_entry = tk.Entry(self.root, font=("Arial", 12))
     self.search_policy_entry.grid(row=7, column=1, padx=10, pady=10)
     ttk.Button(self.root, text="Search", command=self.search_policy).grid(row=7, column=2, padx=10, pady=10)

      # Add theme toggle button
     self.toggle_theme_button = ttk.Button(self.root, text="Switch to Dark Mode", command=self.toggle_theme)
     self.toggle_theme_button.grid(row=7, column=3, columnspan=4, pady=10)

    # Adjust grid weights to allow the log viewer to expand with the window
     self.root.grid_rowconfigure(10, weight=1)
     self.root.grid_columnconfigure(0, weight=1)
     self.root.grid_columnconfigure(1, weight=1)
     self.root.grid_columnconfigure(2, weight=1)
     self.root.grid_columnconfigure(3, weight=1)

    def apply_theme(self, theme):
        self.root.configure(bg=theme['bg'])
        
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Label):
                widget.configure(bg=theme['bg'], fg=theme['fg'])
            elif isinstance(widget, (tk.Button, ttk.Button)):
                widget.configure(style="TButton")
            elif isinstance(widget, tk.Entry):
                widget.configure(bg=theme['entry_bg'], fg=theme['entry_fg'])
            elif isinstance(widget, scrolledtext.ScrolledText):
                widget.configure(bg=theme['log_bg'], fg=theme['log_fg'])
            elif isinstance(widget, tk.Text):
                widget.configure(bg=theme['text_bg'], fg=theme['text_fg'])
    
    def toggle_theme(self):
        if self.current_theme == self.light_mode:
            self.current_theme = self.dark_mode
            self.toggle_theme_button.configure(text="Switch to Light Mode")
        else:
            self.current_theme = self.light_mode
            self.toggle_theme_button.configure(text="Switch to Dark Mode")
        self.apply_theme(self.current_theme)
  
    def clear_logs(self):
        self.log_viewer.configure(state='normal')
        self.log_viewer.delete(1.0,tk.END)
        self.log_viewer.configure(state='disabled')

    def search_user(self):
        user_name = self.search_user_entry.get().strip() # Correct assign the username
        if not user_name:
            messagebox.showerror("Input Error","Please enter a user name.")
            return
    
        logging.info(f'Starting search for user: {user_name}')

        def search_user_thread():
            try:
                response = self.iam.get_user(UserName=user_name)
                user_info = response['User']
                name = user_info['UserName']
                arn = user_info['Arn']
                message = f'User found:\nName: {name}\nArn: {arn}'
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
            except ClientError as e:
                error_message = f"Error finding user: {e}"
                self.root.after(0,lambda: self.log_handler.update_log_viewer(error_message))
        
        # Ensure thread is started only once
        search_thread = threading.Thread(target=search_user_thread,daemon=True)
        search_thread.start()
    
    def search_role(self):
        role_name = self.search_role_entry.get().strip()
        if not role_name:
            messagebox.showerror(f"Input Error","Please enter role name.")
            return
        logging.info(f'Starting search for role: {role_name}')
        def search_role_thread():
            try:
                response = self.iam.get_role(RoleName=role_name)
                role_info = response['Role']
                name = role_info['RoleName']
                arn = role_info['Arn']
                message = f"Role found:\nName: {name}\nArn: {arn}"
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
            except ClientError as e:
                error_message = f"Error finding role: {e}"
                self.root.after(0,lambda: self.log_handler.update_log_viewer(error_message))

        threading.Thread(target=search_role_thread,daemon=True).start()


    def search_policy(self):
        def perform_policy_search(policy_name):
            try:
                # Fetch the list of policies
                policies = self.iam.list_policies(Scope='Local',MaxItems=1000)
                found = False
                results = []
                # Search for policies matching the name
                for policy in policies['Policies']:
                    if policy_name.lower() in policy['PolicyName'].lower(): # Case Insensitive-search
                        name = policy['PolicyName']
                        arn = policy['Arn']
                        results.append(f"Policy found:\nName: {name}\nArn: {arn}")
                        found = True
                if not found:
                    results.append(f"No policy found with the name containing: {policy_name}")
                
                # Format the results message
                message = "\n".join(results)
                # Update the log viewer with the search results
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
            
            except ClientError as e:
                error_message = f"An errror occurred: {e}"
                # Update the log viewer with the error message
                self.root.after(0,lambda: self.log_handler.update_log_viewer(error_message))

        # Fetch the policy name from the entry Entry Widget
        policy_name = self.search_policy_entry.get()
        if not policy_name:
            logging.info("No policy name entered.")
            return
        
        # Run the search in a seperate thread
        threading.Thread(target=perform_policy_search,args=(policy_name,)).start()

    def create_user(self):
        # Collect user input on the main thread
        user_name = simpledialog.askstring("Create User", "Enter username:")
        if not user_name:
            return  # If the user cancels the input or doesn't provide a username, return immediately

        # Validate the username to ensure it meets AWS standards
        if not self.validate_username(user_name):
            messagebox.showerror("Invalid Username", "The username provided does not meet AWS naming standards.")
            return

        # Collect the password immediately after username input
        password = simpledialog.askstring("Create User", "Enter password (leave empty if no custom password):", show='*')
        
        # Ensure the user doesn't create an account if they press cancel on the password dialog
        if password is None:
            return

        # Validate the password if provided
        if password and not self.validate_password(password):
            messagebox.showerror("Weak Password", "The password does not meet security standards.")
            return

        # Start the user creation task in the background to keep the UI responsive
        asyncio.create_task(self._task(user_name, password))

    async def _task(self, user_name, password):
        try:
            # Use a thread pool for blocking I/O operations
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor() as pool:
                response = await loop.run_in_executor(pool, self.sts.get_caller_identity)
                account_id = response['Account']

                # Create the user
                await loop.run_in_executor(pool, self.iam.create_user, {'UserName': user_name})

                # Set a custom password if provided
                if password:
                    await loop.run_in_executor(pool, self.iam.create_login_profile, {
                        'UserName': user_name, 
                        'Password': password, 
                        'PasswordResetRequired': False
                    })

                user_console_link = f"https://{account_id}.signin.aws.amazon.com/console"
                log_message = f'User {user_name} created successfully.\nUser Console Link: {user_console_link}'
                self.root.after(0, lambda: self.log_handler.update_log_viewer(log_message))

        except self.iam.exceptions.EntityAlreadyExistsException:
            log_message = f'User {user_name} already exists.'
            self.root.after(0, lambda: self.log_handler.update_log_viewer(log_message))
        except ClientError as e:
            log_message = f'ClientError creating user {user_name}: {e}'
            self.root.after(0, lambda: self.log_handler.update_log_viewer(log_message))
        except Exception as e:
            log_message = f'Error creating user {user_name}: {e}'
            self.root.after(0, lambda: self.log_handler.update_log_viewer(log_message))

    def validate_username(self, username):
        # AWS IAM username constraints: Usernames must be alphanumeric and/or the following symbols: =,.@-
        if len(username) < 1 or len(username) > 64:
            return False
        if not re.match(r'^[a-zA-Z0-9+=,.@-]+$', username):
            return False
        return True

    def validate_password(self, password):
        # Example password policy: at least 8 characters, including one uppercase letter, one lowercase letter, one digit, and one special character
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False 
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[@$!%*?&]', password):
            return False
        return True

    def list_users(self):
        def task():
            try:
                # List all users
                response = self.iam.list_users()
                users = response.get('Users',[])

                if not users:
                    message = "No user found."
                    self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
                    return
                
                users_info = []
                for user in users:
                    user_name = user['UserName']
                    try:
                        # List attached policies for the user
                        policy_response = self.iam.list_attached_user_policies(UserName=user_name)
                        policies = policy_response.get('AttachedPolicies', [])
                        policy_arn = [policy['PolicyArn'] for policy in policies]
                        policies_text = ", ".join(policy_arn) if policy_arn else "No policies attached."
                    except ClientError as e:
                        policies_text = f"Error fetching policies: {e}"
                    
                    # Collect all user's information
                    user_info = f'User: {user_name}\nPolicies: {policies_text}\n'
                    users_info.append(user_info)
                
                # Log all user's information
                users_text = "\n".join(users_info)
                message = f'Users listed successfully:\n{users_text}'
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))

            except ClientError as e:
                message = f'ClientError listing users: {e}'
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
            except Exception as e:
                message = f'Error listing users: {e}'
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
        
        # Start the thread
        threading.Thread(target=task,daemon=True).start()


    def delete_user(self):
     def fetch_users():
        try:
            users = self.iam.list_users().get('Users', [])
            return [user['UserName'] for user in users]
        except ClientError as e:
            logging.error(f"ClientError fetching users: {e}")
            messagebox.showerror("Error", f"Error fetching users: {e}")
            return []

     def prompt_for_user_deletion():
        # Create a Toplevel window for user selection
        select_user_window = Toplevel(self.root)
        select_user_window.title("Select User to Delete")

        # Fetch users and populate the combobox
        users = fetch_users()
        if not users:
            messagebox.showerror("Error", "No users found or unable to fetch users.")
            return  # Exit if no users found or error occurred

        selected_user = StringVar()

        user_combobox = ttk.Combobox(select_user_window, textvariable=selected_user, values=users, state="readonly")
        user_combobox.grid(row=0, column=0, padx=10, pady=10)
        user_combobox.current(0)  # Set the default selection

        def confirm_deletion():
            user_name = selected_user.get()
            if user_name:
                if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete user {user_name}?", parent=select_user_window):
                    select_user_window.destroy()
                    user_deletion_task(user_name)

        delete_button = ttk.Button(select_user_window, text="Delete", command=confirm_deletion)
        delete_button.grid(row=1, column=0, padx=10, pady=10)

     def user_deletion_task(user_name):
        try:
            # Delete login profile if exists
            try:
                self.iam.delete_login_profile(UserName=user_name)
                logging.info(f'Login profile for user {user_name} deleted successfully.')
            except self.iam.exceptions.NoSuchEntityException:
                logging.info(f'No login profile for user {user_name}. Skipping.')

            # Delete Access keys
            access_keys = self.iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
            for key in access_keys:
                self.iam.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
                logging.info(f'Access key {key["AccessKeyId"]} for user {user_name} deleted successfully.')

            # Delete inline policies
            inline_policies = self.iam.list_user_policies(UserName=user_name).get('PolicyNames', [])
            for policy_name in inline_policies:
                self.iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                logging.info(f'Inline policy {policy_name} for user {user_name} deleted successfully.')

            # Detach and delete attached policies
            attached_policies = self.iam.list_attached_user_policies(UserName=user_name).get('AttachedPolicies', [])
            for policy in attached_policies:
                self.iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
                logging.info(f'Policy {policy["PolicyArn"]} detached from user {user_name} successfully.')

            # Delete MFA Devices
            mfa_devices = self.iam.list_mfa_devices(UserName=user_name).get('MFADevices', [])
            for mfadevice in mfa_devices:
                self.iam.deactivate_mfa_device(UserName=user_name, SerialNumber=mfadevice['SerialNumber'])
                self.iam.delete_virtual_mfa_device(SerialNumber=mfadevice['SerialNumber'])
                logging.info(f'MFA Device {mfadevice["SerialNumber"]} for user {user_name} deleted successfully.')

            # Finally, delete the user
            self.iam.delete_user(UserName=user_name)
            logging.info(f'User {user_name} deleted successfully.')

            # Update GUI and show success message on the main thread
            message = f"User {user_name} deleted successfully."
            self.root.after(0, messagebox.showinfo, "Success", message)
            self.root.after(0, self.log_handler.update_log_viewer, message)

        except self.iam.exceptions.NoSuchEntityException:
            logging.error(f'User {user_name} does not exist.')
            self.root.after(0, messagebox.showerror, "Error", f'User {user_name} does not exist.')
        except ClientError as e:
            logging.error(f'ClientError deleting user {user_name}: {e}')
            self.root.after(0, messagebox.showerror, "Error", f'ClientError deleting user {user_name}: {e}')
        except Exception as e:
            logging.error(f'Error deleting user {user_name}: {e}')
            self.root.after(0, messagebox.showerror, "Error", f'Error deleting user {user_name}: {e}')

     # Start the process by showing the user selection dialog
     threading.Thread(target=prompt_for_user_deletion, daemon=True).start()

    def create_role(self):
     def prompt_for_role_name():
        # Focus on the main window before showing the dialog
        self.root.lift()  # Bring the window to the front
        role_name = simpledialog.askstring("Create Role", "Enter role name:", parent=self.root)
        self.root.focus_set()  # Set focus back to the main window
        return role_name

     def prompt_for_account_choice():
        # Create a Toplevel window for account choice
        choice_window = Toplevel(self.root)
        choice_window.title("Choose Account")

        # Variable to store the user's choice
        account_choice = StringVar(value="This Account")

        # Create Radiobuttons for account choices
        Radiobutton(choice_window, text="This Account", variable=account_choice, value="This Account").pack(anchor="w", padx=10, pady=5)
        Radiobutton(choice_window, text="Another Account", variable=account_choice, value="Another Account").pack(anchor="w", padx=10, pady=5)

        def confirm_choice():
            choice_window.destroy()

        # Create Confirm button
        Button(choice_window, text="Confirm", command=confirm_choice).pack(pady=10)

        # Wait for the user to make a selection
        choice_window.wait_window(choice_window)
        return account_choice.get()

     def prompt_for_external_account_id():
        # Focus on the main window before showing the dialog
        self.root.lift()
        account_id = simpledialog.askstring("External Account ID", "Enter the external AWS Account ID to trust:", parent=self.root)
        self.root.focus_set()
        return account_id

     def generate_trust_policy(account_choice, external_account_id=None):
        if account_choice == "This Account":
            account_id = self.iam.get_caller_identity()['Account']
        else:
            account_id = external_account_id

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{account_id}:root"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        return trust_policy

     # Get role name
     role_name = prompt_for_role_name()
     if not role_name:
        return  # Exit if role name is not provided
 
     # Get account choice for trust policy
     account_choice = prompt_for_account_choice()
     if not account_choice:
        return  # Exit if account choice is not provided

     external_account_id = None
     if account_choice == "Another Account":
        external_account_id = prompt_for_external_account_id()
        if not external_account_id:
            return  # Exit if external account ID is not provided

     # Generate trust policy
     trust_policy = generate_trust_policy(account_choice, external_account_id)

     def role_creation_task():
        try:
            # Create role with the generated trust policy
            self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            success_message = f'Role {role_name} created successfully.'
            logging.info(success_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(success_message))
        except self.iam.exceptions.EntityAlreadyExistsException:
            error_message = f'Role {role_name} already exists.'
            logging.error(error_message)
            self.root.after(0, lambda: messagebox.showerror("Error", error_message, parent=self.root))
        except ClientError as e:
            error_message = f'ClientError creating role {role_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: messagebox.showerror("Error", error_message, parent=self.root))
        except Exception as e:
            error_message = f'Unexpected error creating role {role_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: messagebox.showerror("Error", error_message, parent=self.root))

     # Create and start the thread
     thread = threading.Thread(target=role_creation_task, daemon=True)
     thread.start()

    def delete_role(self):
     def fetch_roles():
        try:
            roles = self.iam.list_roles().get('Roles', [])
            return [role['RoleName'] for role in roles]
        except ClientError as e:
            logging.error(f"ClientError fetching roles: {e}")
            messagebox.showerror("Error", f"Error fetching roles: {e}")
            return []

     def prompt_for_role_deletion():
        # Create a Toplevel window for role selection
        select_role_window = Toplevel(self.root)
        select_role_window.title("Select Role to Delete")

        # Fetch roles and populate the combobox
        roles = fetch_roles()
        if not roles:
            return  # Exit if no roles found or error occurred

        selected_role = StringVar()  # Correctly use StringVar from tkinter

        role_combobox = ttk.Combobox(select_role_window, textvariable=selected_role, values=roles, state="readonly")
        role_combobox.grid(row=0, column=0, padx=10, pady=10)
        role_combobox.current(0)  # Set the default selection

        def confirm_deletion():
            role_name = selected_role.get()
            if role_name:
                if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete role {role_name}?", parent=select_role_window):
                    select_role_window.destroy()
                    role_deletion_task(role_name)

        delete_button = ttk.Button(select_role_window, text="Delete", command=confirm_deletion)
        delete_button.grid(row=1, column=0, padx=10, pady=10)

     def role_deletion_task(role_name):
        try:
            # Detach attached policies
            attached_policies = self.iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
            if attached_policies:
                for policy in attached_policies:
                    self.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
                    success_message = f'Policy {policy["PolicyArn"]} detached from role {role_name} successfully.'
                    logging.info(success_message)
                    self.root.after(0, lambda: self.log_handler.update_log_viewer(success_message))
            else:
                logging.info(f'No attached policies found for role {role_name}.')

            # Delete inline policies
            inline_policies = self.iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])
            if inline_policies:
                for policy_name in inline_policies:
                    self.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                    success_message = f'Inline policy {policy_name} for role {role_name} deleted successfully.'
                    logging.info(success_message)
                    self.root.after(0, lambda: self.log_handler.update_log_viewer(success_message))
            else:
                logging.info(f'No inline policies found for role {role_name}.')

            # Finally, delete the role
            self.iam.delete_role(RoleName=role_name)
            success_message = f'Role {role_name} deleted successfully.'
            logging.info(success_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(success_message))

        except self.iam.exceptions.NoSuchEntityException:
            error_message = f'Role {role_name} does not exist.'
            logging.error(error_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
        except ClientError as e:
            error_message = f'ClientError deleting role {role_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
        except Exception as e:
            error_message = f'Unexpected error deleting role {role_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))

     # Start the process by showing the role selection dialog
     threading.Thread(target=prompt_for_role_deletion, daemon=True).start()

    def list_roles(self):
        """
        List all IAM Roles and their attached policies
        Displays the roles and their policies in the log viewer
        """
        def fetch_policies_for_roles(role_name):
            """
            Fetches and formats the policies attached to a specified IAM role

            Parameters:
            role_name (str): The name of the IAM Role

            Returns:
            str: formattted string with role name and attached policies for error message.
            """
            try:
                policy_response = self.iam.list_attached_role_policies(RoleName=role_name)
                policies = policy_response.get('AttachedPolicies',[])
                policy_arn = [policy['PolicyArn'] for policy in policies]
                return f'Role: {role_name}\nPolicies: {", ".join(policy_arn) if policy_arn else "No policies attached"}\n'
            except ClientError as e:
                return f'Role: {role_name}\nPolicies: Error fetching policies: {e}\n'
            except Exception as e:
                return f'Role: {role_name}\nPolicies: Error fetching policies: {e}\n'
            
        def list_roles_thread():
            """
            Lists all IAM Roles and fetches their attached policies.
            Updates the log viewer with the roles and policies informatio.
            """
            try:
                # List all roles
                response = self.iam.list_roles()
                roles = response.get('Roles',[])

                if not roles:
                    message = 'No roles found'
                    self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
                    return
                
                roles_info = []
                role_names = [role['RoleName'] for role in roles]

                # Fetch policies for all roles in parallel
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_role = {executor.submit(fetch_policies_for_roles, role_name): role_name for role_name in role_names}
                    for future in future_to_role:
                        role_info = future.result()
                        roles_info.append(role_info)
                
                # Logg all roles' information
                roles_text = "\n".join(roles_info)
                message = f'Roles listed: \n{roles_text}'
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))

            except ClientError as e:
                message = f'ClientError listing roles: {e}'
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
            except Exception as e:
                message = f'Error listing roles: {e}'
                self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
        
        # Start the thread
        threading.Thread(target=list_roles_thread,daemon=True).start()
    
    def attach_role_policy(self):
     """
    Attaches a policy to an IAM role.
    Prompts the user for role name and policy ARN, then attaches the policy to the specified role.
     """
     # Prompt for role name
     role_name = simpledialog.askstring("Attach Policy", "Enter role name:")
 
     # If the user pressed "Cancel" or provided empty input, simply return
     if role_name is None or not role_name:
        logging.info("User canceled the role name input dialog.")
        return

     # Prompt for policy ARN
     policy_arn = simpledialog.askstring("Attach Policy", "Enter policy ARN:")

     # If the user pressed "Cancel" or provided empty input, simply return
     if policy_arn is None or not policy_arn:
        logging.info("User canceled the policy ARN input dialog.")
        return

     def process_attachment():
        """
        Handles attaching the policy to the role and updates the log viewer.
        """
        try:
            # Attach the policy to the role
            self.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            message = f'Policy {policy_arn} attached to role {role_name} successfully.'
            logging.info(message)
        except self.iam.exceptions.NoSuchEntityException:
            message = f'Role {role_name} or policy {policy_arn} does not exist.'
            logging.error(message)
        except ClientError as e:
            message = f'ClientError attaching policy {policy_arn} to role {role_name}: {e}'
            logging.error(message)
        except Exception as e:
            message = f'Unexpected error attaching policy {policy_arn} to role {role_name}: {e}'
            logging.error(message)

        # Update the GUI on the main thread
        self.root.after(0, lambda: self.log_handler.update_log_viewer(message))
 
     # Start the process in a new thread
     threading.Thread(target=process_attachment, daemon=True).start()
    
    def detach_role_policy(self):
     """
    Detaches a policy from an IAM role.
    Prompts the user for the role name and policy ARN, then detaches the policy from the specified role.
     """
     # Get role name from the user
     role_name = simpledialog.askstring("Detach Policy", "Enter role name:")
    
     # If the user pressed "Cancel" or provided empty input, simply return
     if role_name is None or not role_name:
        logging.info("User canceled the role name input dialog.")
        return

     # Get policy ARN from the user
     policy_arn = simpledialog.askstring("Detach Policy", "Enter Policy ARN:")

     # If the user pressed "Cancel" or provided empty input, simply return
     if policy_arn is None or not policy_arn:
        logging.info("User canceled the policy ARN input dialog.")
        return

     def process_detachment():
        """
        Handles detaching the policy from the role and updates the log viewer.
        """
        try:
            # Detach the policy from the role
            self.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            message = f'Policy {policy_arn} detached from role {role_name} successfully.'
            logging.info(message)
        except self.iam.exceptions.NoSuchEntityException:
            message = f'Role {role_name} or policy {policy_arn} does not exist.'
            logging.error(message)
        except ClientError as e:
            message = f'ClientError detaching policy {policy_arn} from role {role_name}: {e}'
            logging.error(message)
        except Exception as e:
            message = f'Unexpected error detaching policy {policy_arn} from role {role_name}: {e}'
            logging.error(message)

        # Update the GUI on the main thread
        self.root.after(0, lambda: self.log_handler.update_log_viewer(message))

     # Start the process in a new thread
     threading.Thread(target=process_detachment, daemon=True).start()

    def create_policy(self):
        """
        Creates an IAM policy with the specified name and policy document JSON.
        Prompts the user to enter a policy name and the JSON Document for the policy.
        Validates the input and creates the policy in a seperate thread, ensuring the GUI remains responsive. Logs all action and updates the log viewer with the result.
        """
        # Prompt for policy and document
        policy_name = simpledialog.askstring("Create a policy","Enter policy name:")
        policy_document = simpledialog.askstring("Create policy","Enter policy document JSON:")

        if not policy_name or not policy_document:
            message = 'Policy name and policy document must be provided.'
            logging.error(message)
            self.root.after(0,lambda: messagebox.showerror("Error"),message)
            return
        
        if not self.validate_json(policy_document):
            message = 'Invalid JSON format for policy document.'
            logging.error(message)
            self.root.after(0,lambda: messagebox.showerror("Error",message))
            return
        
        # Function to handle policy creation and updating the log viewer 
        def process_creation():
            try:
                response = self.iam.create_policy(
                    PolicyName=policy_name,
                    PolicyDocument=policy_document
                )
                message = f'Policy {policy_name} created successfully. ARN: {response["Policy"]["Arn"]}'
                logging.info(message)
            except self.iam.exceptions.EntityAlreadyExistsException:
                message = f'Policy {policy_name} already exists.'
                logging.error(message)
            except ClientError as e:
                message = f'ClientError creating policy {policy_name}: {e}'
                logging.error(message)
            except Exception as e:
                message = f'Unexpected error creating policy {policy_name}: {e}'
                logging.error(message)
            
            # Update the GUI on the main thread
            self.root.after(0,lambda: self.log_handler.update_log_viewer(message))
        
        # start the policy creation process in a seperate thread
        threading.Thread(target=process_creation,daemon=True).start()
    
    def list_policies(self):
        def list_policies_thread():
            try:
                policies_info = []
                response = self.iam.list_policies(Scope='All')

                policies = response.get('Policies', [])
                if not policies:
                    message = "No policies found."
                    logging.info(message)
                    self.root.after(0, lambda: self.log_handler.update_log_viewer(message))
                    return

                # Collect policy names and ARNs
                for policy in policies:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['Arn']
                    policies_info.append(f"{policy_name} - {policy_arn}")

                # Combine all policy info into a single string
                policies_text = "\n".join(policies_info)
                logging.info('Policies listed successfully.')

                # Update the GUI on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(policies_text))

            except ClientError as e:
                error_message = f'ClientError listing policies: {e}'
                logging.error(error_message)
                # Update the GUI on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
            except Exception as e:
                error_message = f'Error listing policies: {e}'
                logging.error(error_message)
                # Update the GUI on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))

        # Start a new thread for listing policies
        threading.Thread(target=list_policies_thread, daemon=True).start()
     
  
   
    def delete_policy(self):
        def prompt_for_policy_arn():
            policy_arn = simpledialog.askstring("Delete Policy", "Enter policy ARN:")
            if policy_arn:
                if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete policy {policy_arn}?"):
                    self.run_deletion(policy_arn)

        # Schedule the input prompt to be executed on the main thread
        self.root.after(0, prompt_for_policy_arn)

    def run_deletion(self, policy_arn):
          def delete_policy():
             try:
                self.iam.delete_policy(PolicyArn=policy_arn)
                log_message = f'Policy {policy_arn} deleted successfully.'
                logging.info(log_message)
                # Update the GUI on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(log_message))
                messagebox.showinfo("Success", log_message)
             except self.iam.exceptions.NoSuchEntityException:
                error_message = f'Policy {policy_arn} does not exist.'
                logging.error(error_message)
                # Update the GUI on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
                messagebox.showerror("Error", error_message)
             except ClientError as e:
                error_message = f'ClientError deleting policy {policy_arn}: {e}'
                logging.error(error_message)
                # Update the GUI on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
                messagebox.showerror("Error", error_message)
             except Exception as e:
                error_message = f'Error deleting policy {policy_arn}: {e}'
                logging.error(error_message)
                # Update the GUI on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
                messagebox.showerror("Error", error_message)

          # Start a new thread for deleting the policy
          threading.Thread(target=delete_policy,daemon=True).start()


    def create_group(self):
     def run_creation(group_name):
        if group_name:
            try:
                # Perform the IAM group creation in a separate thread
                self.iam.create_group(GroupName=group_name)
                log_message = f'Group {group_name} created successfully.'
                logging.info(log_message)

                # Schedule GUI updates and message boxes to run on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(log_message))
                self.root.after(0, lambda: messagebox.showinfo("Success", log_message))

            except self.iam.exceptions.EntityAlreadyExistsException:
                error_message = f'Group {group_name} already exists.'
                logging.error(error_message)

                # Schedule GUI updates and message boxes to run on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
                self.root.after(0, lambda: messagebox.showerror("Error", error_message))

            except ClientError as e:
                error_message = f'ClientError creating group {group_name}: {e}'
                logging.error(error_message)

                # Schedule GUI updates and message boxes to run on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
                self.root.after(0, lambda: messagebox.showerror("Error", error_message))

            except Exception as e:
                error_message = f'Error creating group {group_name}: {e}'
                logging.error(error_message)

                # Schedule GUI updates and message boxes to run on the main thread
                self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
                self.root.after(0, lambda: messagebox.showerror("Error", error_message))

     # Run the dialog prompt on the main thread
     group_name = simpledialog.askstring("Create Group", "Enter group name:")
     if group_name:
        # Start a new thread for the run_creation method with the group name as an argument
        threading.Thread(target=run_creation, args=(group_name,)).start()



    def delete_group(self):
     def run_deletion(group_name):
        if not group_name:
            return

        try:
            # Detach all policies
            attached_policies = self.iam.list_attached_group_policies(GroupName=group_name).get('AttachedPolicies', [])
            for policy in attached_policies:
                self.iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])
                logging.info(f'Policy {policy["PolicyArn"]} detached from group {group_name} successfully.')

            # Remove all users
            group_members = self.iam.get_group(GroupName=group_name).get('Users', [])
            for user in group_members:
                self.iam.remove_user_from_group(GroupName=group_name, UserName=user['UserName'])
                logging.info(f'User {user["UserName"]} removed from group {group_name}.')

            # Finally delete the group
            self.iam.delete_group(GroupName=group_name)
            success_message = f'Group {group_name} deleted successfully.'
            logging.info(success_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(success_message))
            self.root.after(0, lambda: messagebox.showinfo("Success", success_message))

        except self.iam.exceptions.NoSuchEntityException:
            error_message = f'Group {group_name} does not exist.'
            logging.error(error_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
            self.root.after(0, lambda: messagebox.showerror("Error", error_message))
        except ClientError as e:
            error_message = f'ClientError deleting group {group_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
            self.root.after(0, lambda: messagebox.showerror("Error", error_message))
        except Exception as e:
            error_message = f'Error deleting group {group_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: self.log_handler.update_log_viewer(error_message))
            self.root.after(0, lambda: messagebox.showerror("Error", error_message))

     # Use the main thread to ask for the group name
     group_name = simpledialog.askstring("Delete Group", "Enter group name:")
     if group_name:
        # Start a new thread for deleting the group
        threading.Thread(target=run_deletion, args=(group_name,), daemon=True).start()
