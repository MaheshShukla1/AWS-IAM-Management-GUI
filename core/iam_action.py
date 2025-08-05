import sys
import json
import os
import boto3
import logging
import re
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QGridLayout, QLabel,
    QPushButton, QTextEdit, QWidget, QMessageBox, QInputDialog,
    QHBoxLayout, QComboBox, QDialog, QFormLayout, QLineEdit,
)
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from botocore.exceptions import ClientError
from gui.layout import Worker

class IAMActions:
    def __init__(self, iam_client, sts_client, log_handler):
        self.iam = iam_client
        self.sts = sts_client
        self.log_handler = log_handler

def create_user(self):
     """
     Creates a new AWS IAM user with optional login profile.
     """
     if not self.validate_profile():
        return

     # Prompt for user name
     user_name, ok = QInputDialog.getText(self, "Create User", "Enter username:")
     if not ok or not user_name:
        return

     # Validate the username based on AWS IAM naming rules
     if not self.validate_username(user_name):
        QMessageBox.critical(self, "Invalid Username",
                             "The username must be alphanumeric and can include _+=,.@-. Max length is 64 characters.")
        logging.error(f"Invalid username: {user_name}")
        return

     # Prompt for password (optional)
     password, ok = QInputDialog.getText(self, "Create User", "Enter password (leave empty for no custom password):", QLineEdit.Password)
     if not ok:
        return

     # Validate password if provided
     if password and not self.validate_password(password):
        QMessageBox.critical(self, "Weak Password",
                             "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
        logging.error(f"Weak password provided for user {user_name}")
        return

     # Call the global perform_task function with arguments
     self.perform_task(self._task_create_user, user_name, password)
 
    def _task_create_user(self, user_name, password):
      """
      Background task to create a user and an optional login profile.
      """
       try:
         logging.info(f"Starting user creation process for {user_name}.")
         response = self.sts.get_caller_identity()
         account_id = response['Account']

         # Create the user
         self.iam.create_user(UserName=user_name)

         # If a password is provided, create the login profile
         if password:
            self.iam.create_login_profile(UserName=user_name, Password=password, PasswordResetRequired=False)
            logging.info(f"Login profile created for user {user_name}.")

         # Generate a user console login link
         user_console_link = f"https://{account_id}.signin.aws.amazon.com/console"
         logging.info(f"User {user_name} created successfully. Console link generated.")

         return f'User {user_name} created successfully.\nUser Console Link: {user_console_link}'

       except self.iam.exceptions.EntityAlreadyExistsException:
        logging.warning(f"User {user_name} already exists.")
        return f'User {user_name} already exists.'

       except ClientError as e:
        logging.error(f"ClientError creating user {user_name}: {e}")
        return f'ClientError creating user {user_name}: {e}'

       except Exception as e:
        logging.critical(f"Unexpected error creating user {user_name}: {e}")
        return f'Error creating user {user_name}: {e}'

     ### Supporting Functions for Validation
      def validate_username(self, username):
       """
      Validates the username according to AWS IAM naming rules:
      - Must be a string of characters consisting of upper and lowercase alphanumeric characters with no spaces.
      - Can also include the following characters: _+=,.@-
      - Must not exceed 64 characters.
      """
      if len(username) > 64:
         return False

      username_pattern = r'^[a-zA-Z0-9_+=,.@-]+$'
      return bool(re.match(username_pattern, username))

     def validate_password(self, password):
       """
      Ensures the password meets a set of security standards.
      You can customize these rules based on your requirements.
      For example:
      - At least 8 characters
      - Contains uppercase, lowercase, number, and special character
       """
       if len(password) < 8:
        return False

       password_pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+]).{8,}$'
       return bool(re.match(password_pattern, password))

def list_users(self):
     """
    Triggers a background task to list all AWS IAM users, and display them in the log viewer.
     """
     if not self.validate_profile():  # Ensure a profile is selected
        return

     # Use the global perform_task to manage threading
     self.perform_task(self._task_list_users)

    def _task_list_users(self):
     """
    Background task to list users and their attached policies.
     """
     try:
        logging.info("Fetching list of IAM users.")
        response = self.iam.list_users()
        users = response.get('Users', [])

        if not users:
            logging.info("No users found in the current AWS account.")
            return "No users found."

        users_info = []
        for user in users:
            user_name = user['UserName']
            logging.info(f"Fetching policies for user: {user_name}")

            # Fetch attached policies for the user
            policy_response = self.iam.list_attached_user_policies(UserName=user_name)
            policies = policy_response.get('AttachedPolicies', [])
            policy_arns = [policy['PolicyArn'] for policy in policies]
            policies_text = ", ".join(policy_arns) if policy_arns else "No policies attached."

            user_info = f'User: {user_name}\nPolicies: {policies_text}\n'
            users_info.append(user_info)

        logging.info(f"Successfully fetched {len(users)} users.")
        return "\n".join(users_info)

     except ClientError as e:
        logging.error(f"ClientError while listing users: {e}")
        return f'ClientError listing users: {e}'

     except Exception as e:
        logging.critical(f"Unexpected error listing users: {e}")
        return f'Error listing users: {e}'

    def delete_user(self):
     # Ensure the IAM client is initialized
     if not self.iam:
        QMessageBox.critical(self, "Error", "AWS IAM client is not initialized. Please select a valid profile.")
        return

     # Fetch the list of users
     users = self._fetch_users()
     if not users:
        QMessageBox.critical(self, "Error", "No users found or unable to fetch users.")
        return

     # Prompt user to select a user for deletion
     user_name, ok = QInputDialog.getItem(self, "Delete User", "Select user to delete:", users, 0, False)
     if not ok or not user_name:
        return

     # Perform the delete operation using a worker thread
     worker = Worker(self._task_delete_user, user_name)
     worker.result.connect(self.log_handler.update_log_viewer)
     worker.error.connect(self.log_handler.update_log_viewer)
     worker.start()

    def _fetch_users(self):
     try:
        # Ensure IAM client is initialized
        if not self.iam:
            raise Exception("AWS IAM client is not initialized. Please select a valid profile.")
        
        # List users from IAM
        users = self.iam.list_users().get('Users', [])
        return [user['UserName'] for user in users]
     except ClientError as e:
        logging.error(f"ClientError fetching users: {e}")
        self.log_handler.update_log_viewer(f"Error fetching users: {e}")
        return []
     except Exception as e:
        logging.error(f"Error fetching users: {e}")
        self.log_handler.update_log_viewer(f"Error fetching users: {e}")
        return []

    def _task_delete_user(self, user_name):
     try:
        # Ensure IAM client is initialized
        if not self.iam:
            raise Exception("AWS IAM client is not initialized. Please select a valid profile.")
        
        # Delete login profile
        try:
            self.iam.delete_login_profile(UserName=user_name)
        except self.iam.exceptions.NoSuchEntityException:
            pass  # Continue even if the user doesn't have a login profile

        # Delete access keys
        access_keys = self.iam.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
        for key in access_keys:
            self.iam.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])

        # Delete inline policies
        inline_policies = self.iam.list_user_policies(UserName=user_name).get('PolicyNames', [])
        for policy_name in inline_policies:
            self.iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)

        # Detach managed policies
        attached_policies = self.iam.list_attached_user_policies(UserName=user_name).get('AttachedPolicies', [])
        for policy in attached_policies:
            self.iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])

        # Deactivate and delete MFA devices
        mfa_devices = self.iam.list_mfa_devices(UserName=user_name).get('MFADevices', [])
        for mfadevice in mfa_devices:
            self.iam.deactivate_mfa_device(UserName=user_name, SerialNumber=mfadevice['SerialNumber'])
            self.iam.delete_virtual_mfa_device(SerialNumber=mfadevice['SerialNumber'])

        # Finally, delete the user
        self.iam.delete_user(UserName=user_name)
        return f'User {user_name} deleted successfully.'

     except self.iam.exceptions.NoSuchEntityException:
        return f'User {user_name} does not exist.'
     except ClientError as e:
        logging.error(f"ClientError deleting user {user_name}: {e}")
        return f'ClientError deleting user {user_name}: {e}'
     except Exception as e:
        logging.error(f"Error deleting user {user_name}: {e}")
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
     # Get group name input
     group_name, ok = QInputDialog.getText(self, "Detach Group Policy", "Enter group name:")
     if not ok or not group_name:
        self.log_handler.update_log_viewer("Group name input cancelled or empty.")
        logging.warning("Group name input cancelled or not provided.")
        return

     # Get policy ARN input
     policy_arn, ok = QInputDialog.getText(self, "Detach Group Policy", "Enter policy ARN:")
     if not ok or not policy_arn:
        self.log_handler.update_log_viewer("Policy ARN input cancelled or empty.")
        logging.warning("Policy ARN input cancelled or not provided.")
        return

     # Validate if the group exists
     try:
        response = self.iam.get_group(GroupName=group_name)
        if response.get("Group"):
            self.log_handler.update_log_viewer(f"Group {group_name} found. Proceeding with detaching policy.")
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

     # Try detaching the policy from the group
     try:
        self.iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        self.log_handler.update_log_viewer(f"Policy {policy_arn} successfully detached from group {group_name}.")
        logging.info(f"Policy {policy_arn} detached from group {group_name} successfully.")
     except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchEntity':
            self.log_handler.update_log_viewer(f"Policy {policy_arn} is not attached to group {group_name}.")
            logging.error(f"Policy {policy_arn} is not attached to group {group_name}: {e}")
        elif error_code == 'LimitExceeded':
            self.log_handler.update_log_viewer("Policy detachment rate limit exceeded. Please try again later.")
            logging.error("Rate limit exceeded while detaching policy.")
        else:
            self.log_handler.update_log_viewer(f"Error detaching policy from group {group_name}: {str(e)}")
            logging.error(f"Error detaching policy from group {group_name}: {e}")
     except Exception as e:
        self.log_handler.update_log_viewer(f"Unexpected error occurred: {str(e)}")
        logging.error(f"Unexpected error while detaching policy from group {group_name}: {e}")


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
