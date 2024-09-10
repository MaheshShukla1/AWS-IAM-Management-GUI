import sys
import json
import os
import boto3
import logging
import re
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QGridLayout, QLabel,
    QPushButton, QTextEdit, QWidget, QMessageBox, QInputDialog,
    QHBoxLayout, QComboBox, QDialog, QFormLayout, QLineEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from botocore.exceptions import ClientError

# Constants
PROFILES_FILE = 'profiles.json'
SECRET_KEY_FILE = 'secret.key'

# Function to generate a new secret key if one does not exist
def generate_secret_key():
    if not os.path.exists(SECRET_KEY_FILE):
        key = Fernet.generate_key()
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(key)

# Function to load the secret key securely
def load_secret_key():
    with open(SECRET_KEY_FILE, 'rb') as f:
        key = f.read()
        if len(key) != 44:  # Fernet key should be 32 bytes URL-safe base64-encoded, which is 44 characters.
            raise ValueError("Invalid Fernet key: must be 32 bytes, URL-safe base64-encoded")
        return key

# Validate the strength of the AWS access key and secret key
def validate_aws_credentials(access_key, secret_key):
    access_key_pattern = r'^AKIA[0-9A-Z]{16}$'
    secret_key_pattern = r'^[A-Za-z0-9/+=]{40}$'
    if not re.match(access_key_pattern, access_key):
        raise ValueError("Invalid Access Key ID format.")
    if not re.match(secret_key_pattern, secret_key):
        raise ValueError("Invalid Secret Access Key format.")

# Initialize the key
generate_secret_key()
# Load the key securely
try:
    SECRET_KEY = load_secret_key()
except ValueError as e:
    logging.error(f"Error loading the key: {e}")
    sys.exit(1)

fernet = Fernet(SECRET_KEY)

class LogHandler:
    def __init__(self, text_edit):
        self.text_edit = text_edit

    def update_log_viewer(self, message):
        self.text_edit.append(message)
        self.text_edit.ensureCursorVisible()

class Worker(QThread):
    result = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            if result is not None:
                self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class AddProfileDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New Profile")
        self.setModal(True)
        self.resize(300, 200)

        self.layout = QFormLayout()
        self.setLayout(self.layout)

        self.profile_name_input = QLineEdit()
        self.access_key_input = QLineEdit()
        self.secret_key_input = QLineEdit()
        self.region_input = QLineEdit()

        self.layout.addRow("Profile Name:", self.profile_name_input)
        self.layout.addRow("Access Key ID:", self.access_key_input)
        self.layout.addRow("Secret Access Key:", self.secret_key_input)
        self.layout.addRow("Default Region:", self.region_input)

        self.buttons_layout = QHBoxLayout()
        self.add_button = QPushButton("Add")
        self.cancel_button = QPushButton("Cancel")
        self.buttons_layout.addWidget(self.add_button)
        self.buttons_layout.addWidget(self.cancel_button)
        self.layout.addRow(self.buttons_layout)

        self.add_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

    def get_data(self):
        return {
            'ProfileName': self.profile_name_input.text().strip(),
            'AccessKeyId': self.access_key_input.text().strip(),
            'SecretAccessKey': self.secret_key_input.text().strip(),
            'Region': self.region_input.text().strip() or 'us-east-1'  # Default region
        }

class ProfilesManager:
    def __init__(self, profiles_file=PROFILES_FILE):
        self.profiles_file = profiles_file
        self.profiles = self.load_profiles()

    def load_profiles(self):
        if not os.path.exists(self.profiles_file):
            return {}
        try:
            with open(self.profiles_file, 'r') as f:
                encrypted_profiles = json.load(f)
                return self.decrypt_profiles(encrypted_profiles)
        except (json.JSONDecodeError, Exception) as e:
            logging.error(f"Error loading profiles: {e}")
            return {}

    def save_profiles(self):
        try:
            encrypted_profiles = self.encrypt_profiles(self.profiles)
            with open(self.profiles_file, 'w') as f:
                json.dump(encrypted_profiles, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save profiles: {e}")

    def add_profile(self, profile_data):
        profile_name = profile_data['ProfileName']
        try:
            validate_aws_credentials(profile_data['AccessKeyId'], profile_data['SecretAccessKey'])
        except ValueError as ve:
            raise ve
        if profile_name in self.profiles:
            raise ValueError("Profile already exists.")
        self.profiles[profile_name] = {
            'AccessKeyId': profile_data['AccessKeyId'],
            'SecretAccessKey': profile_data['SecretAccessKey'],
            'Region': profile_data['Region']
        }
        self.save_profiles()

    def delete_profile(self, profile_name):
        if profile_name not in self.profiles:
            raise ValueError("Profile does not exist.")
        del self.profiles[profile_name]
        self.save_profiles()

    def encrypt_profiles(self, profiles):
        encrypted_profiles = {}
        for profile_name, creds in profiles.items():
            encrypted_profiles[profile_name] = {
                'AccessKeyId': fernet.encrypt(creds['AccessKeyId'].encode()).decode(),
                'SecretAccessKey': fernet.encrypt(creds['SecretAccessKey'].encode()).decode(),
                'Region': creds['Region']
            }
        return encrypted_profiles

    def decrypt_profiles(self, encrypted_profiles):
        decrypted_profiles = {}
        for profile_name, creds in encrypted_profiles.items():
            decrypted_profiles[profile_name] = {
                'AccessKeyId': fernet.decrypt(creds['AccessKeyId'].encode()).decode(),
                'SecretAccessKey': fernet.decrypt(creds['SecretAccessKey'].encode()).decode(),
                'Region': creds['Region']
            }
        return decrypted_profiles

class IAMManagerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Window setup
        self.setWindowTitle("AWS IAM Management GUI")
        self.setGeometry(300, 100, 800, 600)

        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layouts
        self.main_layout = QVBoxLayout(central_widget)
        self.top_layout = QHBoxLayout()
        self.grid_layout = QGridLayout()  # Added grid layout for IAM operations buttons
        self.main_layout.addLayout(self.top_layout)
        self.main_layout.addLayout(self.grid_layout)

        # Initialize log handler
        self.log_viewer = QTextEdit(self)
        self.log_viewer.setReadOnly(True)
        self.log_handler = LogHandler(self.log_viewer)

        # Profiles Manager
        self.profiles_manager = ProfilesManager()

        # Profile Selection
        self.profile_label = QLabel("Select Profile:")
        self.profile_combo = QComboBox()
        self.load_profiles_into_combo()
        self.profile_combo.currentTextChanged.connect(self.change_profile)

        # Add and Delete Profile Buttons
        self.add_profile_button = QPushButton("Add Profile")
        self.add_profile_button.clicked.connect(self.add_profile)
        self.delete_profile_button = QPushButton("Delete Profile")
        self.delete_profile_button.clicked.connect(self.delete_profile)

        # Arrange Profile Widgets
        self.top_layout.addWidget(self.profile_label)
        self.top_layout.addWidget(self.profile_combo)
        self.top_layout.addWidget(self.add_profile_button)
        self.top_layout.addWidget(self.delete_profile_button)

        # Initialize AWS Clients
        self.current_profile = None
        self.iam = None
        self.sts = None
        
        # Now call the update_aws_clients after the log handler is initialized
        self.update_aws_clients()

        # Title label
        self.title_label = QLabel("AWS IAM Management")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setStyleSheet("font-size: 20px;")
        self.main_layout.addWidget(self.title_label)

        # IAM Operation Buttons
        self.create_user_button = QPushButton("Create User")
        self.create_user_button.clicked.connect(self.create_user)
        self.grid_layout.addWidget(self.create_user_button, 0, 0)

        self.list_users_button = QPushButton("List Users")
        self.list_users_button.clicked.connect(self.list_users)
        self.grid_layout.addWidget(self.list_users_button, 0, 1)

        self.delete_user_button = QPushButton("Delete User")
        self.delete_user_button.clicked.connect(self.delete_user)
        self.grid_layout.addWidget(self.delete_user_button, 0, 2)

        self.create_role_button = QPushButton("Create Role")
        self.create_role_button.clicked.connect(self.create_role)
        self.grid_layout.addWidget(self.create_role_button, 1, 0)

        self.list_roles_button = QPushButton("List Roles")
        self.list_roles_button.clicked.connect(self.list_roles)
        self.grid_layout.addWidget(self.list_roles_button, 1, 1)

        self.delete_role_button = QPushButton("Delete Role")
        self.delete_role_button.clicked.connect(self.delete_role)
        self.grid_layout.addWidget(self.delete_role_button, 1, 2)

    
        self.attach_role_policy_button = QPushButton("Attach Policy to Role")
        self.attach_role_policy_button.clicked.connect(self.attach_role_policy)
        self.grid_layout.addWidget(self.attach_role_policy_button, 2, 0)

        self.detach_role_policy_button = QPushButton("Detach Policy from Role")
        self.detach_role_policy_button.clicked.connect(self.detach_role_policy)
        self.grid_layout.addWidget(self.detach_role_policy_button, 2, 1)

        self.create_policy_button = QPushButton("Create Policy")
        self.create_policy_button.clicked.connect(self.create_policy)
        self.grid_layout.addWidget(self.create_policy_button, 2, 2)

        self.list_policies_button = QPushButton("List Policies")
        self.list_policies_button.clicked.connect(self.list_policies)
        self.grid_layout.addWidget(self.list_policies_button, 3, 0)

        self.delete_policy_button = QPushButton("Delete Policy")
        self.delete_policy_button.clicked.connect(self.delete_policy)
        self.grid_layout.addWidget(self.delete_policy_button, 3, 1)

        self.create_group_button = QPushButton("Create Group")
        self.create_group_button.clicked.connect(self.create_group)
        self.grid_layout.addWidget(self.create_group_button, 3, 2)

        self.delete_group_button = QPushButton("Delete Group")
        self.delete_group_button.clicked.connect(self.delete_group)
        self.grid_layout.addWidget(self.delete_group_button, 4, 0)

        # New buttons for group and user policy attachment/detachment

        # Attach Group Policy
        self.attach_group_policy_button = QPushButton("Attach Group Policy")
        self.attach_group_policy_button.clicked.connect(self.attach_group_policy)
        self.grid_layout.addWidget(self.attach_group_policy_button, 4, 1)

        # Detach Group Policy
        self.detach_group_policy_button = QPushButton("Detach Group Policy")
        self.detach_group_policy_button.clicked.connect(self.detach_group_policy)
        self.grid_layout.addWidget(self.detach_group_policy_button, 4, 2)

        # Attach User Policy
        self.attach_user_policy_button = QPushButton("Attach User Policy")
        self.attach_user_policy_button.clicked.connect(self.attach_user_policy)
        self.grid_layout.addWidget(self.attach_user_policy_button, 5, 0)

        # Detach User Policy
        self.detach_user_policy_button = QPushButton("Detach User Policy")
        self.detach_user_policy_button.clicked.connect(self.detach_user_policy)
        self.grid_layout.addWidget(self.detach_user_policy_button, 5, 1)

        # Clear Logs button
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        self.grid_layout.addWidget(self.clear_logs_button, 5, 2)

        self.exit_button = QPushButton("Exit")
        self.exit_button.clicked.connect(self.close)
        self.grid_layout.addWidget(self.exit_button, 6, 0)

        # Dark mode toggle button
        self.toggle_theme_button = QPushButton("Switch to Dark Mode")
        self.toggle_theme_button.clicked.connect(self.toggle_theme)
        self.grid_layout.addWidget(self.toggle_theme_button, 6, 1, 1, 2)

        # Log viewer
        self.main_layout.addWidget(self.log_viewer)

        # Set default theme
        self.current_theme = 'light'
        self.apply_theme(self.current_theme)


    def load_profiles_into_combo(self):
        self.profile_combo.clear()
        profiles = self.profiles_manager.profiles
        if profiles:
            self.profile_combo.addItems(profiles.keys())
            self.current_profile = self.profile_combo.currentText()
        else:
            self.profile_combo.addItem("No Profiles Available")
            self.current_profile = None

    def add_profile(self):
        dialog = AddProfileDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            profile_data = dialog.get_data()
            try:
                if not all([profile_data['ProfileName'], profile_data['AccessKeyId'], profile_data['SecretAccessKey']]):
                    raise ValueError("All fields except Region are required.")
                self.profiles_manager.add_profile(profile_data)
                self.load_profiles_into_combo()
                QMessageBox.information(self, "Success", "Profile added successfully.")
            except ValueError as ve:
                QMessageBox.warning(self, "Error", str(ve))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add profile: {e}")

    def delete_profile(self):
        if not self.current_profile:
            QMessageBox.warning(self, "Error", "No profile selected to delete.")
            return
        confirm = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete the profile '{self.current_profile}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            try:
                self.profiles_manager.delete_profile(self.current_profile)
                self.load_profiles_into_combo()
                self.update_aws_clients()
                QMessageBox.information(self, "Success", "Profile deleted successfully.")
            except ValueError as ve:
                QMessageBox.warning(self, "Error", str(ve))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete profile: {e}")

    def change_profile(self, profile_name):
        if profile_name == "No Profiles Available":
            self.current_profile = None
            self.iam = None
            self.sts = None
            self.log_handler.update_log_viewer("No AWS profile selected.")
            return
        self.current_profile = profile_name
        self.update_aws_clients()
        self.log_handler.update_log_viewer(f"Switched to profile: {self.current_profile}")

    def update_aws_clients(self):
        if not self.current_profile:
            self.iam = None
            self.sts = None
            self.log_handler.update_log_viewer("AWS clients are not initialized. Please select a profile.")
            return
        profile = self.profiles_manager.profiles[self.current_profile]
        try:
            session = boto3.Session(
                aws_access_key_id=profile['AccessKeyId'],
                aws_secret_access_key=profile['SecretAccessKey'],
                region_name=profile['Region']
            )
            self.iam = session.client('iam')
            self.sts = session.client('sts')
            self.log_handler.update_log_viewer(f"AWS clients initialized for profile: {self.current_profile}")
        except ClientError as ce:
            logging.error(f"AWS ClientError: {ce}")
            self.log_handler.update_log_viewer(f"Failed to initialize AWS clients: {ce}")
            self.iam = None
            self.sts = None
        except Exception as e:
            logging.error(f"Error initializing AWS clients: {e}")
            self.log_handler.update_log_viewer(f"Error initializing AWS clients: {e}")
            self.iam = None
            self.sts = None

    def apply_theme(self, theme):
        if theme == 'dark':
            self.setStyleSheet("""
                QWidget {
                    background-color: #333333;
                    color: #ffffff;
                }
                QPushButton {
                    background-color: #555555;
                    color: #ffffff;
                    border: 1px solid #444444;
                    padding: 5px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #666666;
                }
                QTextEdit {
                    background-color: #444444;
                    color: #ffffff;
                    border: 1px solid #333333;
                }
                QLineEdit, QComboBox {
                    background-color: #555555;
                    color: #ffffff;
                    border: 1px solid #444444;
                }
                QDialog {
                    background-color: #333333;
                    color: #ffffff;
                }
            """)
            self.toggle_theme_button.setText("Switch to Light Mode")
            self.current_theme = 'dark'
        else:
            self.setStyleSheet("""
                QWidget {
                    background-color: #f5f5f5;
                    color: #000000;
                }
                QPushButton {
                    background-color: #e0e0e0;
                    border: 1px solid #c0c0c0;
                    padding: 5px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #d0d0d0;
                }
                QTextEdit {
                    background-color: #ffffff;
                    color: #000000;
                    border: 1px solid #c0c0c0;
                }
                QLineEdit, QComboBox {
                    background-color: #ffffff;
                    color: #000000;
                    border: 1px solid #c0c0c0;
                }
                QDialog {
                    background-color: #f5f5f5;
                    color: #000000;
                }
            """)
            self.toggle_theme_button.setText("Switch to Dark Mode")
            self.current_theme = 'light'

    def toggle_theme(self):
        if self.current_theme == 'light':
            self.apply_theme('dark')
        else:
            self.apply_theme('light')

    def clear_logs(self):
        self.log_viewer.clear()

    def create_user(self):
        user_name, ok = QInputDialog.getText(self, "Create User", "Enter username:")
        if not ok or not user_name:
            return

        if not self.validate_username(user_name):
            QMessageBox.critical(self, "Invalid Username", "The username provided does not meet AWS naming standards.")
            return

        password, ok = QInputDialog.getText(self, "Create User", "Enter password (leave empty if no custom password):", QLineEdit.Password)
        if not ok:
            return

        if password and not self.validate_password(password):
            QMessageBox.critical(self, "Weak Password", "The password does not meet security standards.")
            return

        worker = Worker(self._task_create_user, user_name, password)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_create_user(self, user_name, password):
        try:
            response = self.sts.get_caller_identity()
            account_id = response['Account']

            self.iam.create_user(UserName=user_name)
            if password:
                self.iam.create_login_profile(UserName=user_name, Password=password, PasswordResetRequired=False)

            user_console_link = f"https://{account_id}.signin.aws.amazon.com/console"
            return f'User {user_name} created successfully.\nUser Console Link: {user_console_link}'

        except self.iam.exceptions.EntityAlreadyExistsException:
            return f'User {user_name} already exists.'
        except ClientError as e:
            return f'ClientError creating user {user_name}: {e}'
        except Exception as e:
            return f'Error creating user {user_name}: {e}'

    def list_users(self):
        worker = Worker(self._task_list_users)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_list_users(self):
        try:
            response = self.iam.list_users()
            users = response.get('Users', [])
            if not users:
                return "No users found."

            users_info = []
            for user in users:
                user_name = user['UserName']
                policy_response = self.iam.list_attached_user_policies(UserName=user_name)
                policies = policy_response.get('AttachedPolicies', [])
                policy_arn = [policy['PolicyArn'] for policy in policies]
                policies_text = ", ".join(policy_arn) if policy_arn else "No policies attached."
                user_info = f'User: {user_name}\nPolicies: {policies_text}\n'
                users_info.append(user_info)

            return "\n".join(users_info)

        except ClientError as e:
            return f'ClientError listing users: {e}'
        except Exception as e:
            return f'Error listing users: {e}'

    def delete_user(self):
        users = self._fetch_users()
        if not users:
            QMessageBox.critical(self, "Error", "No users found or unable to fetch users.")
            return

        user_name, ok = QInputDialog.getItem(self, "Delete User", "Select user to delete:", users, 0, False)
        if not ok or not user_name:
            return

        worker = Worker(self._task_delete_user, user_name)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _fetch_users(self):
        try:
            users = self.iam.list_users().get('Users', [])
            return [user['UserName'] for user in users]
        except ClientError as e:
            logging.error(f"ClientError fetching users: {e}")
            return []

    def _task_delete_user(self, user_name):
        try:
            self.iam.delete_login_profile(UserName=user_name)
            access_keys = self.iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
            for key in access_keys:
                self.iam.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
            inline_policies = self.iam.list_user_policies(UserName=user_name).get('PolicyNames', [])
            for policy_name in inline_policies:
                self.iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
            attached_policies = self.iam.list_attached_user_policies(UserName=user_name).get('AttachedPolicies', [])
            for policy in attached_policies:
                self.iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
            mfa_devices = self.iam.list_mfa_devices(UserName=user_name).get('MFADevices', [])
            for mfadevice in mfa_devices:
                self.iam.deactivate_mfa_device(UserName=user_name, SerialNumber=mfadevice['SerialNumber'])
                self.iam.delete_virtual_mfa_device(SerialNumber=mfadevice['SerialNumber'])
            self.iam.delete_user(UserName=user_name)
            return f'User {user_name} deleted successfully.'

        except self.iam.exceptions.NoSuchEntityException:
            return f'User {user_name} does not exist.'
        except ClientError as e:
            return f'ClientError deleting user {user_name}: {e}'
        except Exception as e:
            return f'Error deleting user {user_name}: {e}'

    def create_role(self):
        role_name, ok = QInputDialog.getText(self, "Create Role", "Enter role name:")
        if not ok or not role_name:
            return

        account_choice = QMessageBox.question(self, "Choose Account", "Is this for the current account?",
                                              QMessageBox.Yes | QMessageBox.No)
        if account_choice == QMessageBox.No:
            external_account_id, ok = QInputDialog.getText(self, "External Account ID", "Enter the external AWS Account ID to trust:")
            if not ok or not external_account_id:
                return
        else:
            external_account_id = None

        worker = Worker(self._task_create_role, role_name, external_account_id)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_create_role(self, role_name, external_account_id):
        try:
            if external_account_id:
                account_id = external_account_id
            else:
                account_id = self.sts.get_caller_identity()['Account']

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

            self.iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
            return f'Role {role_name} created successfully.'

        except self.iam.exceptions.EntityAlreadyExistsException:
            return f'Role {role_name} already exists.'
        except ClientError as e:
            return f'ClientError creating role {role_name}: {e}'
        except Exception as e:
            return f'Error creating role {role_name}: {e}'

    def delete_role(self):
        roles = self._fetch_roles()
        if not roles:
            QMessageBox.critical(self, "Error", "No roles found or unable to fetch roles.")
            return

        role_name, ok = QInputDialog.getItem(self, "Delete Role", "Select role to delete:", roles, 0, False)
        if not ok or not role_name:
            return

        worker = Worker(self._task_delete_role, role_name)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _fetch_roles(self):
        try:
            roles = self.iam.list_roles().get('Roles', [])
            return [role['RoleName'] for role in roles]
        except ClientError as e:
            logging.error(f"ClientError fetching roles: {e}")
            return []

    def _task_delete_role(self, role_name):
        try:
            attached_policies = self.iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
            for policy in attached_policies:
                self.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
            inline_policies = self.iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])
            for policy_name in inline_policies:
                self.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            self.iam.delete_role(RoleName=role_name)
            return f'Role {role_name} deleted successfully.'

        except self.iam.exceptions.NoSuchEntityException:
            return f'Role {role_name} does not exist.'
        except ClientError as e:
            return f'ClientError deleting role {role_name}: {e}'
        except Exception as e:
            return f'Error deleting role {role_name}: {e}'

    def list_roles(self):
        worker = Worker(self._task_list_roles)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_list_roles(self):
        try:
            roles = self.iam.list_roles().get('Roles', [])
            if not roles:
                return "No roles found."

            roles_info = []
            for role in roles:
                role_name = role['RoleName']
                policy_response = self.iam.list_attached_role_policies(RoleName=role_name)
                policies = policy_response.get('AttachedPolicies', [])
                policy_arn = [policy['PolicyArn'] for policy in policies]
                policies_text = ", ".join(policy_arn) if policy_arn else "No policies attached."
                roles_info.append(f'Role: {role_name}\nPolicies: {policies_text}\n')

            return "\n".join(roles_info)

        except ClientError as e:
            return f'ClientError listing roles: {e}'
        except Exception as e:
            return f'Error listing roles: {e}'

    def attach_role_policy(self):
        role_name, ok = QInputDialog.getText(self, "Attach Policy", "Enter role name:")
        if not ok or not role_name:
            return

        policy_arn, ok = QInputDialog.getText(self, "Attach Policy", "Enter policy ARN:")
        if not ok or not policy_arn:
            return

        worker = Worker(self._task_attach_role_policy, role_name, policy_arn)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_attach_role_policy(self, role_name, policy_arn):
        try:
            self.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            return f'Policy {policy_arn} attached to role {role_name} successfully.'
        except self.iam.exceptions.NoSuchEntityException:
            return f'Role {role_name} or policy {policy_arn} does not exist.'
        except ClientError as e:
            return f'ClientError attaching policy {policy_arn} to role {role_name}: {e}'
        except Exception as e:
            return f'Error attaching policy {policy_arn} to role {role_name}: {e}'

    def detach_role_policy(self):
        role_name, ok = QInputDialog.getText(self, "Detach Policy", "Enter role name:")
        if not ok or not role_name:
            return

        policy_arn, ok = QInputDialog.getText(self, "Detach Policy", "Enter Policy ARN:")
        if not ok or not policy_arn:
            return

        worker = Worker(self._task_detach_role_policy, role_name, policy_arn)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_detach_role_policy(self, role_name, policy_arn):
        try:
            self.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            return f'Policy {policy_arn} detached from role {role_name} successfully.'
        except self.iam.exceptions.NoSuchEntityException:
            return f'Role {role_name} or policy {policy_arn} does not exist.'
        except ClientError as e:
            return f'ClientError detaching policy {policy_arn} from role {role_name}: {e}'
        except Exception as e:
            return f'Error detaching policy {policy_arn} from role {role_name}: {e}'

    def create_policy(self):
        policy_name, ok = QInputDialog.getText(self, "Create Policy", "Enter policy name:")
        if not ok or not policy_name:
            return

        policy_document, ok = QInputDialog.getText(self, "Create Policy", "Enter policy document JSON:")
        if not ok or not policy_document:
            return

        if not self.validate_json(policy_document):
            QMessageBox.critical(self, "Error", "Invalid JSON format for policy document.")
            return

        worker = Worker(self._task_create_policy, policy_name, policy_document)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_create_policy(self, policy_name, policy_document):
        try:
            response = self.iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=policy_document
            )
            return f'Policy {policy_name} created successfully. ARN: {response["Policy"]["Arn"]}'
        except self.iam.exceptions.EntityAlreadyExistsException:
            return f'Policy {policy_name} already exists.'
        except ClientError as e:
            return f'ClientError creating policy {policy_name}: {e}'
        except Exception as e:
            return f'Error creating policy {policy_name}: {e}'

    def list_policies(self):
        worker = Worker(self._task_list_policies)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_list_policies(self):
        try:
            policies_info = []
            response = self.iam.list_policies(Scope='All')

            policies = response.get('Policies', [])
            if not policies:
                return "No policies found."

            for policy in policies:
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                policies_info.append(f"{policy_name} - {policy_arn}")

            return "\n".join(policies_info)

        except ClientError as e:
            return f'ClientError listing policies: {e}'
        except Exception as e:
            return f'Error listing policies: {e}'

    def delete_policy(self):
        policy_arn, ok = QInputDialog.getText(self, "Delete Policy", "Enter policy ARN:")
        if not ok or not policy_arn:
            return

        worker = Worker(self._task_delete_policy, policy_arn)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_delete_policy(self, policy_arn):
        try:
            self.iam.delete_policy(PolicyArn=policy_arn)
            return f'Policy {policy_arn} deleted successfully.'
        except self.iam.exceptions.NoSuchEntityException:
            return f'Policy {policy_arn} does not exist.'
        except ClientError as e:
            return f'ClientError deleting policy {policy_arn}: {e}'
        except Exception as e:
            return f'Error deleting policy {policy_arn}: {e}'

    def create_group(self):
        group_name, ok = QInputDialog.getText(self, "Create Group", "Enter group name:")
        if not ok or not group_name:
            return

        worker = Worker(self._task_create_group, group_name)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_create_group(self, group_name):
        try:
            self.iam.create_group(GroupName=group_name)
            return f'Group {group_name} created successfully.'
        except self.iam.exceptions.EntityAlreadyExistsException:
            return f'Group {group_name} already exists.'
        except ClientError as e:
            return f'ClientError creating group {group_name}: {e}'
        except Exception as e:
            return f'Error creating group {group_name}: {e}'

    def delete_group(self):
        group_name, ok = QInputDialog.getText(self, "Delete Group", "Enter group name:")
        if not ok or not group_name:
            return

        worker = Worker(self._task_delete_group, group_name)
        worker.result.connect(self.log_handler.update_log_viewer)
        worker.error.connect(self.log_handler.update_log_viewer)
        worker.start()

    def _task_delete_group(self, group_name):
        try:
            attached_policies = self.iam.list_attached_group_policies(GroupName=group_name).get('AttachedPolicies', [])
            for policy in attached_policies:
                self.iam.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])

            group_members = self.iam.get_group(GroupName=group_name).get('Users', [])
            for user in group_members:
                self.iam.remove_user_from_group(GroupName=group_name, UserName=user['UserName'])

            self.iam.delete_group(GroupName=group_name)
            return f'Group {group_name} deleted successfully.'

        except self.iam.exceptions.NoSuchEntityException:
            return f'Group {group_name} does not exist.'
        except ClientError as e:
            return f'ClientError deleting group {group_name}: {e}'
        except Exception as e:
            return f'Error deleting group {group_name}: {e}'

    def validate_username(self, username):
        if len(username) < 1 or len(username) > 64:
            return False
        if not re.match(r'^[a-zA-Z0-9+=,.@-]+$', username):
            return False
        return True

    def validate_password(self, password):
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

    def validate_json(self, json_str):
        try:
            json.loads(json_str)
            return True
        except ValueError:
            return False


    def attach_group_policy(self):
     # Get group name input
     group_name, ok = QInputDialog.getText(self, "Attach Group Policy", "Enter group name:")
     if not ok or not group_name:
        self.log_handler.update_log_viewer("Group name input cancelled or empty.")
        return

     # Get policy ARN input
     policy_arn, ok = QInputDialog.getText(self, "Attach Group Policy", "Enter policy ARN:")
     if not ok or not policy_arn:
        self.log_handler.update_log_viewer("Policy ARN input cancelled or empty.")
        return

     # Validate if the group exists before attaching the policy
     try:
        response = self.iam.get_group(GroupName=group_name)
        if response.get("Group"):
            self.log_handler.update_log_viewer(f"Group {group_name} found. Proceeding with attaching policy.")
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"Group {group_name} does not exist.")
            logging.error(f"Group {group_name} does not exist: {e}")
        else:
            self.log_handler.update_log_viewer(f"Error verifying group existence: {str(e)}")
            logging.error(f"Error verifying group {group_name}: {e}")
        return  # Stop further execution if group does not exist or an error occurred

     # Validate if the policy exists
     try:
        response = self.iam.get_policy(PolicyArn=policy_arn)
        if not response.get("Policy"):
            self.log_handler.update_log_viewer(f"Policy {policy_arn} does not exist.")
            logging.error(f"Policy {policy_arn} does not exist.")
            return
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"Policy {policy_arn} does not exist.")
            logging.error(f"Policy {policy_arn} does not exist: {e}")
        else:
            self.log_handler.update_log_viewer(f"Error verifying policy existence: {str(e)}")
            logging.error(f"Error verifying policy {policy_arn}: {e}")
        return

     # Try attaching the policy to the group
     try:
        self.iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        self.log_handler.update_log_viewer(f"Policy {policy_arn} successfully attached to group {group_name}.")
        logging.info(f"Policy {policy_arn} attached to group {group_name} successfully.")
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"Policy {policy_arn} is already attached to group {group_name}.")
            logging.error(f"Policy {policy_arn} is already attached to group {group_name}: {e}")
        elif error_code == 'LimitExceeded':
            self.log_handler.update_log_viewer("Policy attachment rate limit exceeded. Please try again later.")
            logging.error("Rate limit exceeded while attaching policy.")
        else:
            self.log_handler.update_log_viewer(f"Error attaching policy to group {group_name}: {str(e)}")
            logging.error(f"Error attaching policy to group {group_name}: {e}")
     except Exception as e:
        self.log_handler.update_log_viewer(f"Unexpected error occurred: {str(e)}")
        logging.error(f"Unexpected error while attaching policy to group {group_name}: {e}")


    def detach_group_policy(self):
        group_name, ok = QInputDialog.getText(self, "Detach Group Policy", "Enter group name:")
        if ok and group_name:
            policy_arn, ok = QInputDialog.getText(self, "Detach Group Policy", "Enter policy ARN:")
            if ok and policy_arn:
                try:
                    self.iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
                    self.log_handler.update_log_viewer(f"Policy {policy_arn} detached from group {group_name}.")
                except ClientError as e:
                    self.log_handler.update_log_viewer(f"Error detaching policy: {str(e)}")
                    logging.error(f"Error detaching policy from group {group_name}: {e}")

    def attach_user_policy(self):
     # Get user name input
     user_name, ok = QInputDialog.getText(self, "Attach User Policy", "Enter user name:")
     if not ok or not user_name:
        self.log_handler.update_log_viewer("User name input cancelled or empty.")
        return

     # Get policy ARN input
     policy_arn, ok = QInputDialog.getText(self, "Attach User Policy", "Enter policy ARN:")
     if not ok or not policy_arn:
        self.log_handler.update_log_viewer("Policy ARN input cancelled or empty.")
        return

     # Validate if the user exists before attaching the policy
     try:
        response = self.iam.get_user(UserName=user_name)
        if response.get("User"):
            self.log_handler.update_log_viewer(f"User {user_name} found. Proceeding with attaching policy.")
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"User {user_name} does not exist.")
            logging.error(f"User {user_name} does not exist: {e}")
        else:
            self.log_handler.update_log_viewer(f"Error verifying user existence: {str(e)}")
            logging.error(f"Error verifying user {user_name}: {e}")
        return  # Stop further execution if user does not exist or error occurred

     # Validate if the policy exists
     try:
        response = self.iam.get_policy(PolicyArn=policy_arn)
        if not response.get("Policy"):
            self.log_handler.update_log_viewer(f"Policy {policy_arn} does not exist.")
            logging.error(f"Policy {policy_arn} does not exist.")
            return
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"Policy {policy_arn} does not exist.")
            logging.error(f"Policy {policy_arn} does not exist: {e}")
        else:
            self.log_handler.update_log_viewer(f"Error verifying policy existence: {str(e)}")
            logging.error(f"Error verifying policy {policy_arn}: {e}")
        return

     # Try attaching the policy to the user
     try:
        self.iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        self.log_handler.update_log_viewer(f"Policy {policy_arn} successfully attached to user {user_name}.")
        logging.info(f"Policy {policy_arn} attached to user {user_name} successfully.")
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"Policy {policy_arn} is already attached to user {user_name}.")
            logging.error(f"Policy {policy_arn} is already attached to user {user_name}: {e}")
        elif error_code == 'LimitExceeded':
            self.log_handler.update_log_viewer("Policy attachment rate limit exceeded. Please try again later.")
            logging.error("Rate limit exceeded while attaching policy.")
        else:
            self.log_handler.update_log_viewer(f"Error attaching policy to user {user_name}: {str(e)}")
            logging.error(f"Error attaching policy to user {user_name}: {e}")
     except Exception as e:
        self.log_handler.update_log_viewer(f"Unexpected error occurred: {str(e)}")
        logging.error(f"Unexpected error while attaching policy to user {user_name}: {e}")


    def detach_user_policy(self):
     # Get user name input
     user_name, ok = QInputDialog.getText(self, "Detach User Policy", "Enter user name:")
     if not ok or not user_name:
        self.log_handler.update_log_viewer("User name input cancelled or empty.")
        return

     # Get policy ARN input
     policy_arn, ok = QInputDialog.getText(self, "Detach User Policy", "Enter policy ARN:")
     if not ok or not policy_arn:
        self.log_handler.update_log_viewer("Policy ARN input cancelled or empty.")
        return

     # Validate if the user exists before detaching policy
     try:
        response = self.iam.get_user(UserName=user_name)
        if response.get("User"):
            self.log_handler.update_log_viewer(f"User {user_name} found. Proceeding with detaching policy.")
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"User {user_name} does not exist.")
            logging.error(f"User {user_name} does not exist: {e}")
        else:
            self.log_handler.update_log_viewer(f"Error verifying user existence: {str(e)}")
            logging.error(f"Error verifying user {user_name}: {e}")
        return  # Stop further execution if user does not exist or error occurred

     # Try detaching the policy from the user
     try:
        self.iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        self.log_handler.update_log_viewer(f"Policy {policy_arn} successfully detached from user {user_name}.")
        logging.info(f"Policy {policy_arn} detached from user {user_name} successfully.")
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"Policy {policy_arn} is not attached to user {user_name}.")
            logging.error(f"Policy {policy_arn} is not attached to user {user_name}: {e}")
        elif error_code == 'LimitExceeded':
            self.log_handler.update_log_viewer("Policy detachment rate limit exceeded. Please try again later.")
            logging.error("Rate limit exceeded while detaching policy.")
        else:
            self.log_handler.update_log_viewer(f"Error detaching policy from user {user_name}: {str(e)}")
            logging.error(f"Error detaching policy from user {user_name}: {e}")
     except Exception as e:
        self.log_handler.update_log_viewer(f"Unexpected error occurred: {str(e)}")
        logging.error(f"Unexpected error while detaching policy from user {user_name}: {e}")
