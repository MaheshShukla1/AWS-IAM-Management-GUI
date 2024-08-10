"""
threading: Used for running multiple operations concurrently in separate threads, which is useful for tasks that should not block the main application, like network requests.

ThreadPoolExecutor: A high-level interface for asynchronously executing callables using a pool of threads, allowing multiple tasks to be executed concurrently.

tkinter: The standard Python interface to the Tk GUI toolkit, used here to create the graphical user interface (GUI) for the application.

boto3: The Amazon Web Services (AWS) SDK for Python, used to interact with AWS services. Here, it's specifically used to interact with the IAM (Identity and Access Management) service.

logging: A standard Python module for tracking events that happen when some software runs. It’s used for debugging, troubleshooting, or auditing purposes.

LogHandler: A custom logging handler defined in an external module (logging_config). This handler is likely configured to output logs to the GUI's text widget.

validate_json, json: Presumably, these are utility functions from a custom validators module, where validate_json might validate JSON structure and json could refer to standard JSON processing.

ClientError: An exception from botocore, the low-level interface of AWS SDK, used to handle errors returned by AWS services.
"""
import threading
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import scrolledtext,ttk,messagebox,simpledialog
import boto3
import logging
from log_handler import LogHandler
from validate_json import validate_json,json
from botocore.exceptions import ClientError


class IAMManagerApp:
    """
    self.root: This is the main window or root widget of the Tkinter application.

    self.root.title(): Sets the title of the application window to "IAM Manager".

    self.root.geometry(): Defines the dimensions of the window (900x600 pixels).

    self.root.configure(): Sets the background color of the window.

    self.iam = boto3.client('iam'): Creates a client for AWS IAM service, allowing you to interact with IAM (e.g., creating users, roles, policies).

    self.dialog_active: A flag that could be used to track whether a dialog is currently active, likely to prevent multiple dialogs from being opened simultaneously.

    self.setup_gui(): Calls the method to set up all the graphical components (buttons, labels, etc.) of the GUI.

    self.log_viewer: A text widget where logs will be displayed. It is a scrolled text area, meaning it can display large amounts of text with a scrollbar.

    self.setup_logging(): Configures the logging to direct log messages to the log_viewer widget.
    """
    def __init__(self,root):
        self.root = root
        self.root.title("AWS IAM Manager")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f0f0")

        # Initialize IAM Client
        self.iam = boto3.client('iam')
        self.sts = boto3.client('sts')
        self.validate_json = validate_json

        # Initialize Dialog State
        self.dialog_active = False

        # Setup Gui Components
        self.setup_gui()

        # Setup logging viewer
        self.log_viewer = scrolledtext.ScrolledText(self.root,height=10,width=100,state='disabled',bg='#ffffff',fg='#000000',font=("Arial",10))
        self.log_viewer.grid(row=9,column=0,columnspan=4,padx=10,pady=10)

        self.setup_logging()
    
    """
    Purpose: This method sets up logging so that all log messages can be displayed in the log_viewer text widget.

    Explanation: logging.getLogger().handlers: Retrieves all handlers currently attached to the root logger.
    isinstance(handler, LogHandler): Checks if a LogHandler is already attached. This prevents adding multiple handlers.
    logging.getLogger().addHandler(LogHandler(self)): Adds the custom LogHandler that sends log messages to the log_viewer.
    """
    def setup_logging(self):
        if not any(isinstance(handler,LogHandler) for handler in logging.getLogger().handlers):
            logging.getLogger().addHandler(LogHandler(self))
    
    """
    Purpose: This method is responsible for creating and placing all the widgets (buttons, labels, etc.) on the window.

    Explanation:

    title_label: A label widget displaying the title "IAM Manager" with a specific font style. It spans across four columns at the top of the grid layout.
    grid(): This is a geometry manager that organizes widgets in a table-like structure within the parent widget.
    """
    def setup_gui(self):
        title_label = tk.Label(self.root,text="IAM Manager",font=("Arial",20,"bold"),bg="#f0f0f0")
        title_label.grid(row=0,column=0,columnspan=4,pady=15)

        """
        ttk.Style(): Used to customize the appearance of ttk widgets, in this case, buttons (TButton).
        button_style.configure(): Configures the button appearance with padding, background color, and font styling.

        button_style.map(): Defines the appearance of the button when it is active (clicked).
        """
        
        button_style = ttk.Style()
        button_style.configure("TButton",padding=6,relief='flat',background="#007bff",foreground="#000000",font=("Arial",10,"bold"))
        button_style.map("TButton",background=[("active","#0056b3")])

        """
        ttk.Button(): Creates a button widget with a specific text label and an associated command to be executed when the button is clicked.

        command=self.create_user: Binds the button to a method that will be called when the button is clicked (e.g., self.create_user).

        grid(): Places the button on the window at the specified grid position.
        """

        ttk.Button(self.root,text="Create User",command=self.create_user).grid(row=1,column=0,padx=10,pady=10)
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
        self.search_user_entry = tk.Entry(self.root)
        self.search_user_entry.grid(row=5, column=1, padx=10, pady=10)
        ttk.Button(self.root, text="Search", command=self.search_user).grid(row=5, column=2, padx=10, pady=10)

        tk.Label(self.root, text="Search Role:", bg="#f0f0f0").grid(row=6, column=0, padx=10, pady=10, sticky="e")
        self.search_role_entry = tk.Entry(self.root)
        self.search_role_entry.grid(row=6, column=1, padx=10, pady=10)
        ttk.Button(self.root, text="Search", command=self.search_role).grid(row=6, column=2, padx=10, pady=10)

        tk.Label(self.root, text="Search Policy (by Name):", bg="#f0f0f0").grid(row=7, column=0, padx=10, pady=10, sticky="e")
        self.search_policy_entry = tk.Entry(self.root)
        self.search_policy_entry.grid(row=7, column=1, padx=10, pady=10)
        ttk.Button(self.root, text="Search", command=self.search_policy).grid(row=7, column=2, padx=10, pady=10)
    """
    Explanation: self.log_viewer.configure(state='normal'): Temporarily enables editing of the text widget (it is usually disabled to prevent user editing).
    self.log_viewer.delete(1.0, tk.END): Deletes all text from the beginning (1.0) to the end (tk.END) of the text widget.
    self.log_viewer.configure(state='disabled'): Re-disables the text widget to prevent further editing.
    """
    def clear_logs(self):
        self.log_viewer.configure(state='normal')
        self.log_viewer.delete(1.0,tk.END)
        self.log_viewer.configure(state='disabled')

    """
    search_user(self) Method
    Purpose:
    This method is responsible for searching a specific IAM user in AWS using the provided username in the GUI. The search result, whether successful or not, is displayed in the log viewer.

    Steps:
    Get User Input: The method starts by retrieving the text from the search_user_entry widget, which is expected to be the username.
    The input is stripped of any leading or trailing whitespace.
    
    Input Validation: If the user doesn't enter a username, a message box (messagebox.showerror) pops up with an "Input Error," asking the user to input a username.
    The method returns early if no username is provided, preventing further execution.

    Logging: An info log is created to note the start of the user search.
    
    Search in a Separate Thread: A search_user_thread function is defined to handle the user search. This allows the search operation to run in the background, keeping the GUI responsive.
    
    Inside this function, the iam.get_user method from the boto3 client is used to fetch the user details.
    If the user is found, their name and ARN (Amazon Resource Name) are retrieved, and a success message is formatted.
    If there's an error (e.g., user not found or AWS permissions issue), a ClientError is caught, and an error message is prepared.

    The result message is then passed to the log viewer using self.root.after(0, lambda: self.update_log_viewer(message)). The after method ensures thread-safe updates to the Tkinter GUI.
    
    Thread Execution: A Thread object is created and started with the target as search_user_thread. This is marked as a daemon thread, meaning it will automatically exit when the main program exits.
    """    

    
    def update_log_viewer(self,message):
        try:
            self.app.log_viewer.configure(state='normal')
            self.app.log_viewer.insert(tk.END,message+'\n')
            self.app.log_viewer.configure(state='disabled')
            self.app.log_viewer.yview(tk.END)
        except Exception as e:
            logging.error(f'Error updating log viewer: {e}')

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
                self.root.after(0,lambda: self.update_log_viewer(message))
            except ClientError as e:
                error_message = f"Error finding user: {e}"
                self.root.after(0,lambda: self.update_log_viewer(error_message))
        
        # Ensure thread is started only once
        search_thread = threading.Thread(target=search_user_thread,daemon=True)
        search_thread.start()

    """
    search_role Method:
    Purpose: Searches for an IAM role by its name.
    
    Input Handling: Retrieves the role name from the search_role_entry widget.
     If the role name is empty, an error message is displayed using messagebox.showerror.

     Logging: Logs the start of the role search.

     Threaded Operation: The actual search is performed in a separate thread (search_role_thread) to keep the UI responsive.
     Calls self.iam.get_role(RoleName=role_name) to fetch the role information from AWS IAM.
     On success, extracts the role name and ARN from the response and updates the log viewer in the main thread using self.root.after.
     If an error occurs (e.g., role not found), it catches the ClientError exception and updates the log viewer with the error message.
     search_policy Method:
     """
    
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
                self.root.after(0,lambda: self.update_log_viewer(message))
            except ClientError as e:
                error_message = f"Error finding role: {e}"
                self.root.after(0,lambda: self.update_log_viewer(error_message))

        threading.Thread(target=search_role_thread,daemon=True).start()


        """
        search_policy Method:
        Purpose: Searches for IAM policies by name, with a partial match.
        
        Threaded Operation: Defines an inner function perform_policy_search that handles the search process.
        Retrieves the list of policies using self.iam.list_policies, limiting the scope to 'Local' and a maximum of 1000 items.
        Iterates over the policies to find those whose names contain the input string (case-insensitive match).

        If a match is found, the policy name and ARN are added to the results list.
        If no match is found, a message indicating no policies were found is added to the results list.
        The results are formatted into a single message string and displayed in the log viewer.
        If an error occurs during the policy search, it catches the ClientError exception and displays an error message.
        
        Input Handling: Retrieves the policy name from the search_policy_entry widget.
        Logs a message if no policy name is entered.

        Threaded Execution: Runs perform_policy_search in a separate thread to maintain UI responsiveness.
        """

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
                self.root.after(0,lambda: self.update_log_viewer(message))
            
            except ClientError as e:
                error_message = f"An errror occurred: {e}"
                # Update the log viewer with the error message
                self.root.after(0,lambda: self.update_log_viewer(error_message))

        # Fetch the policy name from the entry Entry Widget
        policy_name = self.search_policy_entry.get()
        if not policy_name:
            logging.info("No policy name entered.")
            return
        
        # Run the search in a seperate thread
        threading.Thread(target=perform_policy_search,args=(policy_name,)).start()

        """
        The create_user method is designed to create an IAM user on AWS, with optional password setting functionality, all while maintaining the responsiveness of the UI through the use of threading.

        User Input Collection: Prompts the user for a username using simpledialog.askstring. If the user cancels or leaves it blank, the method returns early.
        Prompts for a password with the option to leave it empty. If the user cancels this prompt, the method returns immediately.
        
        Task Function (Threaded): The task of creating the user is handled within a separate thread (task) to prevent the UI from freezing during the operation.
        AWS Account ID: Uses STS (get_caller_identity) to retrieve the AWS account ID, necessary for generating the user console link.
        User Creation: Creates the IAM user with the provided username via create_user.
        Password Handling: If a password is provided, it sets up a login profile for the user with this password using create_login_profile.
        Logging: If successful, it logs a message with the user's console link.
        If the user already exists, it catches the EntityAlreadyExistsException and logs an appropriate message.
        Handles other potential errors like ClientError and generic exceptions, logging relevant messages for each.
        The results are updated in the UI using self.root.after to ensure the UI is updated in the main thread.
        Thread Execution: The task function is executed in a new thread, keeping the main thread (UI) responsive.
        """

    def create_user(self):
        # Collect user input on the main thread
        user_name = simpledialog.askstring("Create User","Enter username:")
        if not user_name:
            return # If the user cancels the input or doesn't provide a username, return immediately.
        
        password = simpledialog.askstring("Create User","Enter password (leave empty if no custom password):",
        show ='*')

        # Ensure doesn't create an account if they pass cancel on password dialog
        if password is None:
            return
        
        def task(user_name,password):
            try:
                # Fetch the AWS Account ID using sts
                response = self.sts.get_caller_identity()
                account_id = response['Account']

                # Create the user
                self.iam.create_user(UserName=user_name)

                # Set a custom password if needed
                if password:
                    self.iam.create_login_profile(UserName=user_name,Password=password,PasswordResetRequired=False)
                
                user_console_link = f"https://{account_id}.signin.aws.amazon.com/console"

                log_message = f"User {user_name} created successfully. \nUser Console Link: {user_console_link}"
                self.root.after(0,lambda: self.update_log_viewer(log_message))
            except self.iam.exceptions.EntityAlreadyExistsException:
                log_message = f"User {user_name} already exists."
                self.root.after(0,lambda: self.update_log_viewer(log_message))
            except ClientError as e:
                log_message = f"ClientError creating user {user_name}: {e}"
                self.root.after(0,lambda: self.update_log_viewer(log_message))
            except Exception as e:
                log_message = f"Error creating user {user_name}: {e}"
                self.root.after(0,lambda: self.update_log_viewer(log_message))


        # Start a new thread for creating a use
        threading.Thread(target=task,args=(user_name,password),daemon=True).start()

        """
        The list_users method is responsible for listing all IAM users in an AWS account and displaying their associated attached policies. It leverages threading to perform the task in the background, ensuring the UI remains responsive.

        Task Function (Threaded): The core functionality is encapsulated within a task function, which is executed in a separate thread to avoid blocking the main thread (UI).
        
        User Listing: Calls self.iam.list_users() to retrieve a list of all IAM users.
        If no users are found, it logs a message saying "No users found."
        
        Policy Retrieval for Each User: For each user, the method attempts to list attached policies using self.iam.list_attached_user_policies.
        Collects the ARNs of the attached policies and formats them as a comma-separated string. If no policies are attached, it notes "No policies attached."
        
        If there's an error fetching policies, it logs the error message.
        User Information Collection: Collects and formats the user's name and attached policy information into a readable format.
        If there are multiple users, it aggregates all their information into a single string.
        
        Logging: After processing all users, it logs the collected information in the UI.
        If there are errors during user listing or policy retrieval, the method catches these errors and logs appropriate error messages.

        Thread Execution: The task function is executed in a new thread, ensuring that the UI remains responsive while the user and policy data are fetched.
        """

    def list_users(self):
        def task():
            try:
                # List all users
                response = self.iam.list_users()
                users = response.get('Users',[])

                if not users:
                    message = "No user found."
                    self.root.after(0,lambda: self.update_log_viewer(message))
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
                self.root.after(0,lambda: self.update_log_viewer(message))

            except ClientError as e:
                message = f'ClientError listing users: {e}'
                self.root.after(0,lambda: self.update_log_viewer(message))
            except Exception as e:
                message = f'Error listing users: {e}'
                self.root.after(0,lambda: self.update_log_viewer(message))
        
        # Start the thread
        threading.Thread(target=task,daemon=True).start()


        """
        The delete_user method facilitates the deletion of an IAM user from AWS, including a comprehensive cleanup of related resources. It uses threading to perform operations in the background, keeping the UI responsive.

        Prompt for Username: Uses simpledialog.askstring to request the username of the IAM user to be deleted.
        If the user provides a username and confirms deletion with messagebox.askyesno, the method proceeds; otherwise, it exits.
        
        Threaded Task Function:
        Delete Login Profile: Attempts to delete the login profile for the user with self.iam.delete_login_profile.
        Logs success if the profile is deleted or skips if it does not exist.

        Delete Access Keys: Lists access keys using self.iam.list_access_keys.
        Deletes each access key using self.iam.delete_access_key and logs the action.

        Delete Inline Policies: Lists inline policies with self.iam.list_user_policies.
        Deletes each inline policy using self.iam.delete_user_policy and logs the action.
        Detach and Delete Attached Policies: Lists attached policies with self.iam.list_attached_user_policies.
        Detaches each policy with self.iam.detach_user_policy and logs the action.

        Delete MFA Devices: Lists MFA devices with self.iam.list_mfa_devices.
        Deactivates and deletes each MFA device using self.iam.deactivate_mfa_device and self.iam.delete_virtual_mfa_device, logging the actions.

        Delete the User: Deletes the user with self.iam.delete_user and logs success.

        Error Handling: Catches and logs errors for non-existent users (NoSuchEntityException), client errors (ClientError), and other exceptions.

        Updates the GUI with appropriate success or error messages using messagebox.showinfo or messagebox.showerror.

        Thread Execution: Executes the user_deletion_task function in a separate thread, ensuring the main thread (UI) remains responsive during the deletion process.
        """

    def delete_user(self):
        user_name = simpledialog.askstring("Delete User","Enter username:")
        if user_name:
            if messagebox.askyesno("Confirm Deletion",f"Are you sure you want to delete user {user_name}"):

                def user_deletion_task():
                    try:
                        # Delete login profile if exists
                        try:
                            self.iam.delete_login_profile(UserName=user_name)
                            logging.info(f'Login profile for user {user_name} deleted successfully.')
                        except self.iam.exceptions.NoSuchEntityException:
                            logging.info(f'No login profile for user {user_name}. Skipping.')

                        # Delete Access keys
                        access_keys = self.iam.list_access_keys(UserName=user_name).get('AccessKeyMetaData',[])
                        for key in access_keys:
                            self.iam.delete_access_key(UserName=user_name,AccessKeyId=key['AccessKeyId'])
                            logging.info(f'Access key {key["AccessKeyId"]} for user {user_name} deleted successfully.')

                        # Delete inline policies
                        inline_policies = self.iam.list_user_policies(UserName=user_name).get('PolicyNames',[])
                        for policy_name in inline_policies:
                            self.iam.delete_user_policy(UserName=user_name,PolicyName=policy_name)
                            logging.info(f'Inline policy {policy_name} for user {user_name} deleted successfully.')
                        
                        # Detach and delete attached policies
                        attached_policies = self.iam.list_attached_user_policies(UserName=user_name).get('AttachedPolicies',[])
                        for policy in attached_policies:
                            self.iam.detach_user_policy(UserName=user_name,PolicyArn=policy['PolicyArn'])
                            logging.info(f'Policy {policy['PolicyArn']} detached from user {user_name} successfully.')

                        # Delete MFA Devices
                        mfa_devices = self.iam.list_mfa_devices(UserName=user_name).get('MFADevices',[])
                        for mfadevice in mfa_devices:
                            self.iam.deactivate_mfa_device(UserName=user_name,SerialNumber=mfadevice['SerialNumber'])
                            self.iam.delete_virtual_mfa_device(SerialNumber=mfadevice['SerialNumber'])
                            logging.info(f'MFA Devices {mfa_devices['SerialNumber']} for user {user_name} deleted successfully.')
                        
                        # Finnaly, delete the user
                        self.iam.delete_user(UserName=user_name)
                        logging.info(f'User {user_name} deleted successfully.')

                        # Update Gui on the main thread
                        self.root.after(0,messagebox.showinfo,"Success",f"User {user_name} deleted successfully.")

                    except self.iam.exceptions.NoSuchEntityException:
                        logging.error(f'User {user_name} does not exist.')
                        self.root.after(0,messagebox.showerror,"Error",f'User {user_name} does not exist.')
                    except ClientError as e:
                        logging.error(f'ClientError deleting user {user_name}: {e}')
                        self.root.after(0,messagebox.showerror,"Error",f'ClientError deleting user {user_name}: {e}')
                    except Exception as e:
                        logging.error(f'Error deleting user {user_name}: {e}')
                        self.root.after(0,messagebox.showerror,"Error",f'Error deleting user {user_name}: {e}')
                
                # Creat and start a thread
                threading.Thread(target=user_deletion_task,daemon=True).start()
        
        """
        2. validate_trust_policy Function
        Purpose: To ensure the trust policy JSON contains a valid Principal field.

        Implementation: Iterates over the Statement field in the trust policy. Checks if each statement includes the Principal field and whether it is a dictionary. Logs errors and displays an error message if validation fails.

        3. Role Name Input
        Functionality: Uses simpledialog.askstring to prompt the user to enter the role name. If no role name is provided, the method exits early.

        4. Trust Policy Input and Validation
        Functionality: Prompts the user to enter the trust policy JSON.

        Validation: Checks if the provided trust policy is valid JSON using validate_json().
        Parses the JSON and validates the structure with validate_trust_policy(). If any validation fails, appropriate error messages are logged and shown.

        5. role_creation_task Function
        Purpose: Contains the logic to create the IAM role using the provided trust policy.

        Implementation: Uses self.iam.create_role to create the role.

        Handles exceptions: EntityAlreadyExistsException: Logs and displays an error if the role already exists.

        ClientError: Logs and displays an error for other client-related issues.

        Exception: Catches any unexpected errors, logs them, and displays an error message.

        UI Update: Uses self.root.after() to ensure that UI updates are performed on the main thread.

        6. Thread Creation and Execution

        Purpose: To run the role creation task in the background, keeping the main thread (UI) responsive.

        Implementation: Creates a new thread and starts it to execute role_creation_task().

        This refactoring enhances code readability and maintainability by: Separating validation logic into dedicated functions.
        Providing clear error handling and logging.
        Ensuring that user interface updates occur on the main thread.
        """



    def create_role(self):
        def validate_trust_policy(trust_policy_obj):
            statements = trust_policy_obj.get("Statement",[])
            for statement in statements:
                if "Principal" not in statement:
                    logging.error("Missing 'Principal' field in trust policy statement.")
                    self.root.after(0,messagebox.showerror,"Error","Trust policy is missing 'Principal' field.")
                    return False
                if not isinstance(statement['Principal'],dict):
                    logging.error("'Principal' field must be an object in trust policy statement.")
                    self.root.after(0,messagebox.showerror,"Error","'Principal' field must be an object.")
                    return False
            return True
        
        role_name = simpledialog.askstring("Create Role","Enter rolename:")
        if not role_name:
            return # Exit if role name is not provided
        
        trust_policy = simpledialog.askstring("Create Role","Enter trust policy JSON:")
        if not validate_json(trust_policy):
            logging.error("Invalid JSON format for trust policy.")
            self.root.after(0,messagebox.showerror,"Error","Invalid JSON format for trust policy.")
            return
        
        try:
            trust_policy_obj = json.loads(trust_policy)
            if not validate_trust_policy(trust_policy_obj):
                return
        except json.JSONDecodeError:
            logging.error("Error decoding trust policy JSON.")
            self.root.after(0,messagebox.showerror,"Error","Error decoding trust policy json")
            return
        
        def role_creation_task():
            try:
                # Create role with the provided trust policy
                self.iam.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=trust_policy
                )
                logging.info(f'Role {role_name} created successfully.')
                self.root.after(0,messagebox.showinfo,"Success",f'Role {role_name} created successfully.')
            except self.iam.exceptions.EntityAlreadyExistsException:
                logging.error(f'Role {role_name} already exists.')
                self.root.after(0,messagebox.showerror,"Error",f'Role {role_name} already exists.')
            except ClientError as e:
                logging.error(f'ClientError creating role: {role_name}: {e}')
                self.root.after(0,messagebox.showerror,"Error",f'ClientError creating role {role_name}: {e}')
            except Exception as e:
                logging.error(f'Unexpected error creating role: {role_name}: {e}')
                self.root.after(0,messagebox.showerror,"Error",f'Unexpected error creating role {role_name}: {e}')
        
        # Create and start the thread
        thread = threading.Thread(target=role_creation_task,daemon=True)
        thread.start()


    def delete_role(self):
        """
        Prompts the user to delete a specified IAM Role. this includes:
        - Confirming the deletion
        - Detaching the deletion
        - Deleting inline policies
        - Removing the role itself
        """

        role_name = simpledialog.askstring("Delete Role","Enter role name:")
        if role_name:
            if not messagebox.askyesno("Confirm deletion",f'Are you sure you want to delete role {role_name}?'):
                logging.info(f'Role deletion for {role_name} was canceled by the user.')
                return
            
        def role_deletion_task():
            """
            Task executed in a seperate thread to delete the IAM Role
            """
            try:
                # Detach attached policies
                attached_policies = self.iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies',[])
                if attached_policies:
                    for policy in attached_policies:
                        self.iam.detach_role_policy(RoleName=role_name,PolicyArn=policy['PolicyArn'])
                        logging.info(f'Policy {policy['PolicyArn']} detached from role {role_name} successfully.')
                else:
                    logging.info(f'No attached policy found for role {role_name}')
                
                # Delete inline policies
                inline_policies = self.iam.list_role_policies(RoleName=role_name).get('PolicyNames',[])
                if inline_policies:
                    for policy_name in inline_policies:
                        self.iam.delete_role_policy(RoleName=role_name,PolicyName=policy_name)
                        logging.info(f'Inline policy {policy_name} for role {role_name} deleted successfully.')
                else:
                    logging.info(f'No inline policies found for role {role_name}')
                
                # Delete the role
                self.iam.delete_role(RoleName=role_name)
                logging.info(f'Role {role_name} deleted successfully.')
            
            except self.iam.exceptions.NoSuchEntityException:
                logging.error(f'Role {role_name} does not exists.')
                self.root.after(0,messagebox.showerror,"Error",f'Role {role_name} does not exists.')
            except ClientError as e:
                logging.error(f'ClientError deleting role {role_name}: {e}')
                self.root.after(0,messagebox.showerror,"Error",f'Unexpected error deleting role {role_name}: {e}')

        # Start the deletion task in a seperate thread
        thread = threading.Thread(target=role_deletion_task)
        thread.start()

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
                    self.root.after(0,lambda: self.update_log_viewer(message))
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
                self.root.after(0,lambda: self.update_log_viewer(message))

            except ClientError as e:
                message = f'ClientError listing roles: {e}'
                self.root.after(0,lambda: self.update_log_viewer(message))
            except Exception as e:
                message = f'Error listing roles: {e}'
                self.root.after(0,lambda: self.update_log_viewer(message))
        
        # Start the thread
        threading.Thread(target=list_roles_thread,daemon=True).start()
    

    """
    attach_role_policy Method:

    Purpose: This method attaches a specified policy to an IAM role. It prompts the user to input the role name and policy ARN, and then processes the attachment in a separate thread.

    User Input: role_name and policy_arn are obtained from the user via simpledialog.askstring. If either is missing, an error message is displayed, and the method returns early.

    process_attachment Function:
    Purpose: Executes the policy attachment process and logs the result.

    Steps:
    Calls self.iam.attach_role_policy to attach the policy to the specified role.

    Logs a success message if the attachment is successful.

    Handles specific exceptions:

    NoSuchEntityException: Indicates that either the role or policy does not exist.

    ClientError: Catches errors related to the AWS client, including issues with permissions or invalid parameters.

    Exception: Catches any other unexpected errors.

    Updates GUI: Uses self.root.after to ensure that updates to the GUI (via update_log_viewer) are performed on the main thread.

    Threading: Starts the process_attachment function in a separate thread to prevent blocking the main application thread. The daemon=True parameter ensures the thread will not prevent the program from exiting if it is still running.
    """
    def attach_role_policy(self):
        """
        Attaches a policy to an IAM role.
        Prompts the user for role name and policy ARN, then attaches the policy to the specified role.
        """
        # Get role name and policy ARN for user input
        role_name = simpledialog.askstring("Attach Policy","Enter role name:")
        policy_arn = simpledialog.askstring("Attach Policy","Enter policy ARN:")


        # Check if user input is valid
        if not role_name or not policy_arn:
            message = 'Role name and policy ARN must be provided.'
            logging.error(message)
            self.root.after(0,lambda: messagebox.showerror("Error",message))
            return
        
        def process_attachement():
            """
            Handles attaching the policy to the role and updates the log viewer.
            """

            try:
                # attach the policy to role
                self.iam.attach_role_policy(RoleName=role_name,PolicyArn=policy_arn)
                message = f'Policy {policy_arn} attached to role {role_name} successfully.'
                logging.info(message)
            except self.iam.exceptions.NoSuchEntityException:
                message = f'Role {role_name} or policy {policy_arn} does not exist.'
                logging.errorr(message)
            except ClientError as e:
                message = f'ClientError attaching a policy {policy_arn} to role {role_name}: {e}'
                logging.error(message)
            except Exception as e:
                message = f'Error attaching policy {policy_arn} to role {role_name}: {e}'
                logging.error(message)

            # Update The gui on the main thread
            self.root.after(0,lambda: self.update_log_viewer(message))

        0# starts the process in a new thread
        threading.Thread(target=process_attachement,daemon=True).start()
    
    def detach_role_policy(self):
        """
        Detaches a policy from an IAM role.
        Prompts the user for the role name and policy ARN, then detaches the policy to the specified role.
        """
        # Get role name and policy ARN from the user
        role_name = simpledialog.askstring("Detach Policy","Enter role name:")
        policy_arn = simpledialog.askstring("Detach Policy","Enter Policy ARN:")

        # Check if user input is valid
        if not role_name or not policy_arn:
            message = 'Role name and PolicyArn must be provided.'
            logging.error(message)
            self.root.after(0,lambda: messagebox.showerror("Error",message))
            return
        
        def process_attachment():
            """
            Handles attaching the policy to the role and updates the log viewer.
            """
            try:
                # Attach the policy to the role 
                self.iam.detach_role_policy(RoleName=role_name,PolicyArn=policy_arn)
                message = f'Policy {policy_arn} detached from role {role_name} successfully.'
                logging.info(message)
            except self.iam.exceptions.NoSuchEntityException:
                message = f'Role {role_name} or policy {policy_arn} successfully.'
                logging.error(message)
            except ClientError as e:
                message = f'Error detaching policy {policy_arn} from role {role_name}: {e}'
                logging.error(message)
            except Exception as e:
                message = f'Error detaching policy {policy_arn} from role {role_name}: {e}'
                logging.error(message)

            # Update the GUI on the main thread
            self.root.after(0,lambda: self.update_log_viewer(message))
        
        # Start the process in a new thread
        threading.Thread(target=process_attachment,daemon=True).start()

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
            self.root.after(0,lambda: self.update_log_viewer(message))
        
        # start the policy creation process in a seperate thread
        threading.Thread(target=process_creation,daemon=True).start()
    
    def list_policies(self):
        """
        List all IAM policies and displays their names and ARNs in the log viewer.
        
        This methods fetches all IAM policies available within the AWS account and displays their names and ARNs. It runs in a seperate thread to ensure the GUi remains responsive.
        """

        def list_policies_thread():
            try:
                policies_info = []
                response = self.iam.list_policies(Scope='All')

                policies = response.get('Policies',[])
                if not policies:
                    message = 'No policies found.'
                    logging.info(message)
                    self.root.after(0,lambda: self.update_log_viewer(message))
                    return
                
                # Collect policy names and ARNs 
                for policy in policies:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['PolicyArn']
                    policies_info.append(f'{policy_name} - {policy_arn}')

                # Combine all policy into a single string
                policies_text = '\n'.join(policies_info)
                logging.info('Policy listed successfully.')

                # Update the GUI on main thread
                self.root.after(0,lambda: self.update_log_viewer(policies_text))
            
            except ClientError as e:
                error_message = f'ClientError listing policies: {e}'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
            except Exception as e:
                error_message = f'Unexpected error occurred: {e}'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
        
        # Start the policy listing process in a new thread.
        threading.Thread(target=list_policies_thread,daemon=True).start()
    
    def delete_policy(self):
        """
        Deletes an IAM policy based on the provided ARN.

        This method prompts the user to enter the Arn of the policy they wish to delete.
        It confirms the deletions with the user and handles the deletion process in a seperate thread to keep the GUI component.
        """
        def run_deletion():
            try:
                policy_arn = simpledialog.askstring("Delete Policy","Enter Policy ARN:")
                if not policy_arn:
                    logging.warning("No policy ARN provided.")
                    self.root.after(0,lambda: messagebox.showwarning("Warning","Policy Arn is required to delete a policy."))
                    return
                
                confirm = messagebox.askyesno("Confirm deletion",f"Are you sure you want to delete policy {policy_arn}")
                if not confirm:
                    logging.info(f"Deletion of policy {policy_arn} canceled by the user.")
                    return
                
                # Attempt to delete the policy
                self.iam.delete_policy(PolicyArn=policy_arn)
                log_message = f"Policy {policy_arn} deleted successfully."
                logging.info(log_message)

                # Update the GUI  and modify the user on the main thread
                self.roto.after(0,lambda: self.update_log_viewer(log_message))
                self.root.after(0,lambda: self.update_log_viewer("Success",log_message))
            
            except self.iam.exceptions.NoSuchEntityException:
                error_message = f'Policy {policy_arn} does not exist.'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
                self.root.after(0,lambda: messagebox.showerror("Error",error_message))
            
            except ClientError as e:
                error_message = f'ClientError deleting policy {policy_arn}: {e}'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
                self.root.after(0,lambda: messagebox.showerror("Error",error_message))
            
            except Exception as e:
                error_message = f'Unexpected error deleting policy {policy_arn}: {e}'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
                self.roto.after(0,lambda: messagebox.showerror("Error",error_message))
            
        # Run the deletion in a new thread to keep the GUI responsive.
        threading.Thread(target=run_deletion,daemon=True).start()

    def create_group(self):
        """
        Creates an IAM group based on the user-provided group name.

        This method prompts the user to enter the name of the group they wish to create, 
        handles the creation process in a seperate thread to keep the GUI response,
        and provides feedback to the user on success or future.
        """

        def run_creation():
            try:
                # Prompt the user for the group name
                group_name = simpledialog.askstring("Create group","Enter group name:")
                if not group_name:
                    logging.warning("No group name provided.")
                    self.root.after(0,lambda: messagebox.showwarning("Warning","Group name is required to create a group."))
                    return
                
                # Attempt to create an IAM Grooup
                self.iam.create_group(GroupName=group_name)
                log_message = f'Group "{group_name}" created successfully.'
                logging.info(log_message)

                # Update the GUI on main thread and notify the user
                self.root.after(0,lambda: self.update_log_viewer(log_message)) 
                self.root.after(0,lambda: messagebox.showinfo("Success",log_message))

            except self.iam.exceptions.EntityAlreadyExistsException:
                error_message = f'Group "{group_name}" already exists.'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
                self.root.after(0,lambda: messagebox.showerror("Error",error_message))
            
            except ClientError as e:
                error_message = f'ClientError creating group {group_name}: {e}'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
                self.root.after(0,lambda: messagebox.showerror("Error",error_message))
            
            except Exception as e:
                error_message = f'Unexpected error creating group: {group_name}: {e}'
                logging.error(error_message)
                self.root.after(0,lambda: self.update_log_viewer(error_message))
                self.root.after(0,lambda: messagebox.showerror("Error",error_message))
            
        # Start a new thread for creating the group to keep the GUI responsive
        threading.Thread(target=run_creation,daemon=True).start()
    
    def delete_group(self):
      """
    Deletes an AWS IAM group along with its associated policies and users.

     This method performs the following actions:
    1. Prompts the user to enter the name of the group to delete.
    2. Detaches all policies attached to the specified group.
    3. Removes all users from the specified group.
    4. Deletes the group itself.

    The method runs in a separate thread to avoid blocking the GUI. It updates the GUI with success or error messages based on the outcome of the operation.

    If the group does not exist or if any other error occurs, appropriate error messages are logged and displayed to the user.

    Usage:
        - User is prompted to enter the group name.
        - Confirm deletion dialog is shown to ensure user intention.
        - Actions are performed in the following order: detach policies, remove users, delete group.
        - Success or error messages are displayed in a message box and logged.

    Exceptions:
        - `self.iam.exceptions.NoSuchEntityException` if the specified group does not exist.
        - `ClientError` for any AWS client errors encountered during the process.
        - `Exception` for any other unexpected errors.

    Note:
        - This method assumes the `self.iam` object is an instance of `boto3` IAM client.
        - The method is run in a separate thread to keep the GUI responsive.
    """
      def run_deletion():
        group_name = simpledialog.askstring("Delete Group", "Enter group name:")
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
            self.root.after(0, lambda: self.update_log_viewer(success_message))
            messagebox.showinfo("Success", success_message)

        except self.iam.exceptions.NoSuchEntityException:
            error_message = f'Group {group_name} does not exist.'
            logging.error(error_message)
            self.root.after(0, lambda: self.update_log_viewer(error_message))
            messagebox.showerror("Error", error_message)
        except ClientError as e:
            error_message = f'ClientError deleting group {group_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: self.update_log_viewer(error_message))
            messagebox.showerror("Error", error_message)
        except Exception as e:
            error_message = f'Error deleting group {group_name}: {e}'
            logging.error(error_message)
            self.root.after(0, lambda: self.update_log_viewer(error_message))
            messagebox.showerror("Error", error_message)

      # Start a new thread for deleting the group
      threading.Thread(target=run_deletion, daemon=True).start()
