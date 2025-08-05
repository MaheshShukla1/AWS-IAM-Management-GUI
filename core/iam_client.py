import logging, boto3, re
from botocore.exceptions import ClientError

# Validate AWS Credentials with logging
def validate_aws_credentials(access_key, secret_key):
    access_key_pattern = r'^AKIA[0-9A-Z]{16}$'
    secret_key_pattern = r'^[A-Za-z0-9/+=]{40}$'
    
    if not re.match(access_key_pattern, access_key):
        logging.error(f"Invalid AWS Access Key ID: {access_key}")
        raise ValueError("Invalid Access Key ID format.")
    
    if not re.match(secret_key_pattern, secret_key):
        logging.error(f"Invalid AWS Secret Access Key: {secret_key}")
        raise ValueError("Invalid Secret Access Key format.")


def update_aws_clients(self):
      """
     Initializes the AWS clients (IAM, STS) for the selected profile with proper error handling.
      """
      # If no profile is selected, reset the AWS clients
      if not self.current_profile:
        logging.error("No profile selected in update_aws_clients.")
        self.iam = None
        self.sts = None
        self.log_handler.update_log_viewer("AWS clients are not initialized. Please select a profile.")
        return

      # Get the profile data from the profiles manager
      profile = self.profiles_manager.profiles.get(self.current_profile)
      if not profile:
        logging.error(f"No profile data found for: {self.current_profile}")
        self.iam = None
        self.sts = None
        self.log_handler.update_log_viewer(f"Error: No profile data found for: {self.current_profile}")
        return

      # Initialize AWS clients with decrypted credentials
      try:
        # Assuming decryption of credentials is handled in the profiles_manager already
        session = boto3.Session(
            aws_access_key_id=profile['AccessKeyId'],
            aws_secret_access_key=profile['SecretAccessKey'],
            region_name=profile['Region']
        )
        self.iam = session.client('iam')
        self.sts = session.client('sts')

        # Confirm clients were successfully initialized
        if self.iam and self.sts:
            logging.info(f"AWS clients initialized for profile: {self.current_profile}")
            self.log_handler.update_log_viewer(f"AWS clients initialized for profile: {self.current_profile}")
        else:
            logging.error(f"Failed to initialize AWS clients for profile: {self.current_profile}")
            self.log_handler.update_log_viewer(f"Failed to initialize AWS clients for profile: {self.current_profile}")
            self.iam = None
            self.sts = None

      except ClientError as ce:
        logging.error(f"AWS ClientError initializing clients for profile {self.current_profile}: {ce}")
        self.log_handler.update_log_viewer(f"Failed to initialize AWS clients: {ce}")
        self.iam = None
        self.sts = None

      except Exception as e:
        logging.critical(f"Unexpected error initializing AWS clients for profile {self.current_profile}: {e}")
        self.log_handler.update_log_viewer(f"Error initializing AWS clients: {e}")
        self.iam = None
        self.sts = None


    
   