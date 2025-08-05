from utils.logger import LogHandler
import json
import os
import logging
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QMainWindow, QVBoxLayout, QGridLayout, QLabel,
    QPushButton, QTextEdit, QWidget, QMessageBox,
    QHBoxLayout, QComboBox, QDialog, QFormLayout, QLineEdit,
)
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from config.constants import PROFILES_FILE
from utils.encryption import fernet
from core.iam_client import validate_aws_credentials
from gui.theme import   apply_theme, toggle_theme
import logging
from core.iam_action import IAMActions


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

    def stop(self):
        self.quit()  # Quit the thread
        self.wait()  # Wait for the thread to finish properly before destruction

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
        self.buttons_laout.addWidget(self.cancel_button)
        self.layout.addRow(self.buttons_layout)

        self.add_button.clicked.connect(self.validate_and_accept)  # Updated
        self.cancel_button.clicked.connect(self.reject)

    def validate_and_accept(self):
        """
        Validates the input fields and accepts the dialog if all fields are valid.
        """
        if not all([self.profile_name_input.text(), self.access_key_input.text(), self.secret_key_input.text()]):
            QMessageBox.warning(self, "Error", "All fields must be filled in.")
            return
        self.accept()

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
        logging.warning(f"{self.profiles_file} does not exist. Returning empty profile list.")
        return {}
     try:
        with open(self.profiles_file, 'r') as f:
            encrypted_profiles = json.load(f)
            decrypted_profiles = self.decrypt_profiles(encrypted_profiles)
            logging.info(f"Loaded and decrypted profiles: {decrypted_profiles}")
            return decrypted_profiles
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
        try:
            decrypted_profiles[profile_name] = {
                'AccessKeyId': fernet.decrypt(creds['AccessKeyId'].encode()).decode(),
                'SecretAccessKey': fernet.decrypt(creds['SecretAccessKey'].encode()).decode(),
                'Region': creds['Region']
            }
        except Exception as e:
            logging.error(f"Error decrypting profile {profile_name}: {e}")
            raise e
     logging.info(f"Decrypted profiles: {decrypted_profiles}")
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
        from utils.logger import LogHandler

        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        log_handler = LogHandler(self)  # self = main app
        logger.addHandler(log_handler)

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
        self.profile_combo.currentIndexChanged.connect(self.change_profile)  # Updated to currentIndexChanged

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
        self.actions = IAMActions(self.iam, self.sts, self.log_handler)


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

        # Policy and Group Buttons
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

        # Group and User Policy Management
        self.attach_group_policy_button = QPushButton("Attach Group Policy")
        self.attach_group_policy_button.clicked.connect(self.attach_group_policy)
        self.grid_layout.addWidget(self.attach_group_policy_button, 4, 1)

        self.detach_group_policy_button = QPushButton("Detach Group Policy")
        self.detach_group_policy_button.clicked.connect(self.detach_group_policy)
        self.grid_layout.addWidget(self.detach_group_policy_button, 4, 2)

        self.attach_user_policy_button = QPushButton("Attach User Policy")
        self.attach_user_policy_button.clicked.connect(self.attach_user_policy)
        self.grid_layout.addWidget(self.attach_user_policy_button, 5, 0)

        self.detach_user_policy_button = QPushButton("Detach User Policy")
        self.detach_user_policy_button.clicked.connect(self.detach_user_policy)
        self.grid_layout.addWidget(self.detach_user_policy_button, 5, 1)

        # Clear Logs and Exit
        self.clear_logs_button = QPushButton("Clear Logs")
        self.clear_logs_button.clicked.connect(self.clear_logs)
        self.grid_layout.addWidget(self.clear_logs_button, 5, 2)

        self.exit_button = QPushButton("Exit")
        self.exit_button.clicked.connect(self.close)
        self.grid_layout.addWidget(self.exit_button, 6, 0)

    def clear_logs(self):
        self.log_viewer.clear()

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
     """
     Loads available profiles into the combo box and auto-selects the first profile.
     """
     self.profile_combo.clear()
     profiles = self.profiles_manager.profiles
     if profiles:
        self.profile_combo.addItems(profiles.keys())
        # Automatically select the first profile
        if self.profile_combo.count() > 0:
            self.profile_combo.setCurrentIndex(0)  # Automatically select the first profile
            self.change_profile(self.profile_combo.currentText())  # Initialize AWS clients for the first profile
            logging.info(f"Profile {self.current_profile} loaded and AWS clients initialized.")
     else:
        self.profile_combo.addItem("No Profiles Available")
        self.current_profile = None
        logging.warning("No profiles available to load.")
        self.log_handler.update_log_viewer("No profiles available.")

    def add_profile(self):
     dialog = AddProfileDialog(self)
     if dialog.exec_() == QDialog.Accepted:
        profile_data = dialog.get_data()
        try:
            if not all([profile_data['ProfileName'], profile_data['AccessKeyId'], profile_data['SecretAccessKey']]):
                raise ValueError("All fields except Region are required.")
            self.profiles_manager.add_profile(profile_data)
            self.load_profiles_into_combo()
            self.profile_combo.setCurrentText(profile_data['ProfileName'])  # Set the new profile as the selected one
            self.update_aws_clients()  # Initialize the clients for the newly added profile
            logging.info(f"Profile {profile_data['ProfileName']} added and selected successfully.")
            QMessageBox.information(self, "Success", "Profile added successfully.")
        except ValueError as ve:
            logging.error(f"Error adding profile: {ve}")
            QMessageBox.warning(self, "Error", str(ve))
        except Exception as e:
            logging.critical(f"Critical error adding profile: {e}")
            QMessageBox.critical(self, "Error", f"Failed to add profile: {e}")


    # Enhanced function for deleting a profile
    def delete_profile(self):
     if not self.current_profile:
        QMessageBox.warning(self, "Error", "No profile selected to delete.")
        logging.error("No profile selected for deletion.")
        return
     confirm = QMessageBox.question(
        self, "Confirm Delete",
        f"Are you sure you want to delete the profile '{self.current_profile}'?",
        QMessageBox.Yes | QMessageBox.No
     )
     if confirm == QMessageBox.Yes:
        try:
            profile_name = self.current_profile
            self.profiles_manager.delete_profile(profile_name)
            self.load_profiles_into_combo()
            self.update_aws_clients()
            logging.info(f"Profile {profile_name} deleted successfully.")
            QMessageBox.information(self, "Success", f"Profile {profile_name} deleted successfully.")
        except ValueError as ve:
            logging.error(f"Error deleting profile: {ve}")
            QMessageBox.warning(self, "Error", str(ve))
        except Exception as e:
            logging.critical(f"Critical error deleting profile: {e}")
            QMessageBox.critical(self, "Error", f"Failed to delete profile: {e}")

    # Validation before performing any AWS operation
    def validate_profile(self):
     """
     Validates if the current profile and AWS clients are correctly initialized.
     """
     if not self.current_profile:
        logging.error("No profile selected.")
        self.log_handler.update_log_viewer("No profile selected. Please select a profile first.")
        return False

     if not self.iam or not self.sts:
        logging.error("AWS clients are not initialized.")
        self.log_handler.update_log_viewer("AWS clients are not initialized. Please select a profile first.")
        return False

     return True


    def change_profile(self, profile_name):
     """
     Handles switching between different AWS profiles and updating the AWS clients.
     """
     if profile_name == "No Profiles Available":
        self.current_profile = None
        self.iam = None
        self.sts = None
        self.log_handler.update_log_viewer("No AWS profile selected.")
        logging.warning("Attempted to switch to 'No Profiles Available'.")
        return

     self.current_profile = profile_name
     logging.info(f"Profile selected: {self.current_profile}")
     self.update_aws_clients()  # Initialize AWS clients based on the selected profile
     self.log_handler.update_log_viewer(f"Switched to profile: {self.current_profile}")


  