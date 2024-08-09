# IAM Manager GUI

![Build Status](https://img.shields.io/github/workflow/status/MaheshShukla1/IAM-Automation-GUI/CI)
![License](https://img.shields.io/github/license/MaheshShukla1/IAM-Automation-GUI)
![Version](https://img.shields.io/github/release/MaheshShukla1/IAM-Automation-GUI)

**IAM Manager GUI** is a powerful tool designed to streamline the management of AWS Identity and Access Management (IAM) resources. With an intuitive graphical user interface (GUI), users can effortlessly create, list, and manage IAM users, roles, policies, and groups. Built with Python’s `boto3` library and `tkinter`, this application simplifies complex IAM tasks and enhances productivity.

## Table of Contents

- [Project Overview](#project-overview)
- [Application Screenshot](#application-screenshot)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Detailed Examples](#detailed-examples)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)
- [Acknowledgements](#acknowledgements)
- [FAQ](#faq)
- [Support](#support)

## Project Overview

IAM Manager GUI simplifies AWS IAM management through a desktop application, offering:

- **User Management**: Effortlessly create, list, and delete IAM users.
- **Role Management**: Manage IAM roles by creating, listing, deleting, and attaching policies.
- **Policy Management**: Create, list, and delete IAM policies.
- **Group Management**: Manage IAM groups, including creation and deletion.
- **Logging**: Comprehensive logging of all actions for monitoring and troubleshooting.

### Application Screenshot
**![iam_manager_gui](https://github.com/user-attachments/assets/53302272-994b-47a0-be0b-ff3ead63dd02)**
**![iam_manager_enter](https://github.com/user-attachments/assets/de7b029f-5851-4d00-a8d0-d85bdc287185)**

## Features

- **User-Friendly GUI**: Provides an intuitive and easy-to-navigate interface for efficient IAM management, designed for both beginners and advanced users.
- **Real-Time Logging**: Captures detailed logs of all actions and events, enabling comprehensive monitoring and troubleshooting.
- **Robust Error Handling**: Features informative error messages and validation checks to guide users and ensure smooth operation.
- **Cross-Platform Compatibility**: Works seamlessly across all platforms that support Python and Tkinter, including Windows, macOS, and Linux.
- **Asynchronous Operations**: Utilizes threading to handle long-running IAM tasks in the background, preventing GUI freeze and ensuring a responsive user experience.
- **Customizable Settings**: Allows users to configure AWS credentials and other settings directly through the application for streamlined management.
- **Secure Authentication**: Handles AWS credentials securely, following best practices to ensure the safety of sensitive information.
- **Comprehensive IAM Management**: Supports essential IAM operations, including user creation, deletion, and management of access keys, policies, and MFA devices.
- **User Confirmation Dialogs**: Implements confirmation dialogs for critical actions like user deletion to prevent accidental operations.
- **Detailed Documentation**: Includes a well-structured README and contributing guidelines to facilitate ease of use and collaboration.
  

## Installation

### Prerequisites

- **Python 3.x**: Ensure that Python 3.x is installed on your system. Tkinter is included with Python installations by default.
- **AWS Credentials**: Configure your AWS credentials using the AWS CLI or by setting up environment variables.

### Installing Dependencies

1. **Clone the Repository**: To get started, clone the repository to your local machine using Git:
    ![git_clone](https://github.com/user-attachments/assets/6672bebb-6052-4dfe-8bcf-2d8c0ad6b67e)

    ```bash 
    git clone https://github.com/MaheshShukla1/IAM-Manager-GUI.git
    ```
    
2. **Navigate to the Project Directory**: Change into the project directory:
    # ![cd](https://github.com/user-attachments/assets/764f0bb4-0f65-46ba-98bb-cf391fa2cd1c)

    ```bash  
    cd IAM-Manager-GUI
    ```
    
3. **Install Python Dependencies**: Install the required Python packages using pip:
    
    ```bash    
    pip install boto3
    ```
    
    The `boto3` library is used for interacting with AWS IAM. Tkinter is included with Python and does not require separate installation.
    
4. **Verify Installation**: Ensure that the dependencies are correctly installed and that Python is set up properly by running a test script or starting the application.
    

## Usage

1. **Configure AWS Credentials**: Set up your AWS credentials with:
   # ![aws_configure](https://github.com/user-attachments/assets/a1646b82-8d49-40b9-9ca7-2f2ec96695c7)

    ```bash
    aws configure
    ```
    
2. **Run the Application**:
    ```python
    python main.py
    ```
    
3. **Using the GUI**:
    
    - **Create User**: Click "Create User", enter the username, and click "Create".
        
    - **List Users**: Click "List Users" to see all IAM users.
        
    - **Delete User**: Click "Delete User", enter the username, and confirm.
        
    - **Create Role**: Click "Create Role", enter role details, and provide trust policy JSON.
        
    - **Delete Role**: Click "Delete Role", enter the role name, and confirm.
        
    - **Attach Policy to Role**: Enter the role name and policy ARN to attach a policy.
        
    - **Detach Policy from Role**: Enter the role name and policy ARN to detach a policy.
        
    - **Create Policy**: Enter policy details and JSON to create a policy.
        
    - **List Policies**: View all IAM policies by clicking "List Policies".
        
    - **Delete Policy**: Remove a policy by entering its name.
        
    - **Create Group**: Create a new IAM group.
        
    - **Delete Group**: Remove an IAM group.
        

## Configuration

Customize `main.py` for your specific needs. Make sure your AWS credentials have the necessary permissions.

### Example Configuration

Add any example configuration settings or code snippets relevant to the project.

## Detailed Examples

### Example 1: Basic User Management

Create a user named "test-user":

1. Go to "Create User".
2. Enter "test-user" and click "Create".

### Example 2: Role Management with Policy Attachment

1. Create a role:
    
    - Go to "Create Role".
    - Enter "test-role" and provide trust policy JSON.
    
2. Attach a policy:
    
    - Go to "Attach Policy to Role".
    - Enter "test-role" and policy ARN.
    

## Troubleshooting

**Q: The application is not starting.**

A: Ensure the following:

- Python 3.x is installed. Verify by running `python --version` in the terminal.
- Dependencies are installed. Run `pip install -r requirements.txt` to install required packages.
- Check if `boto3` and `tkinter` are properly installed. You can test `boto3` by running a simple script that initializes an AWS client, and `tkinter` by running a basic GUI example.

**Q: AWS credentials are not working.**

A: Follow these steps:

- Verify AWS credentials are correctly configured using the AWS CLI. Run `aws configure` and check if the credentials are valid.
- Ensure that the IAM user has the necessary permissions for the operations being performed.
- Check if the AWS credentials are set in the environment variables (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`).

**Q: Application is crashing with a `ClientError`.**

A: This might be due to:

- Invalid permissions or incorrect API usage. Review the AWS IAM policies and ensure the API requests are correct.
- Network issues. Ensure that there is a stable internet connection and that there are no firewall rules blocking the AWS API endpoints.

**Q: Logs are not updating or displaying correctly.**

A: Check the following:

- Ensure the logging configuration is correctly set up and that the `logging` module is properly initialized.
- Verify that the `Text` widget or log display area is properly updated from the main thread using `self.root.after()`.

**Q: Dialog boxes are not displaying or are unresponsive.**

A: Make sure:

- Dialogs are invoked on the main thread. Use `self.root.after()` to schedule UI updates from background threads.
- Ensure that `self.dialog_active` is correctly managed to prevent overlapping dialogs.

**Q: Errors in creating or deleting users.**

A: Verify:

- User input validity. Ensure usernames and passwords meet AWS IAM requirements.
- Check for any AWS-specific limitations or conditions, such as naming constraints and policy attachments.

## Roadmap

**Future Enhancements:**

- **Extended IAM Features:**
    
    - **User Groups Management:** Implement functionalities to create, manage, and delete user groups.
    - **Policy Management:** Add features for creating, attaching, and managing IAM policies.
    - **Role Management:** Include capabilities for creating and managing IAM roles and their permissions.
- **Enhanced GUI Functionalities:**
    
    - **User Interface Improvement:** Refine the UI for better user experience, including advanced dialogs and form validations.
    - **User Feedback Integration:** Provide more interactive and responsive feedback for user actions.
    - **Customizable Views:** Allow users to customize the appearance and layout of the GUI.
- **Logging and Error Handling:**
    
    - **Advanced Logging:** Implement structured logging with additional log levels and external log storage options.
    - **Error Reporting:** Improve error handling with detailed diagnostics and user-friendly error messages.
    - **Automated Testing:** Develop automated tests to ensure robust error handling and logging accuracy.
- **Performance Optimization:**
    
    - **Thread Management:** Optimize threading for improved performance and responsiveness.
    - **Resource Management:** Enhance resource handling to efficiently manage API calls and user data.
- **Documentation and Support:**
    
    - **User Documentation:** Provide comprehensive user guides and FAQs to assist users with common issues and features.
    - **Developer Documentation:** Include detailed API documentation, coding standards, and contribution guidelines for future developers.
- **Security Enhancements:**
    
    - **Secure Authentication:** Implement more secure authentication mechanisms and compliance with best practices.
    - **Data Protection:** Ensure data protection and privacy by integrating encryption and secure storage practices.
- **Feature Expansion:**
    
    - **Multi-Language Support:** Add support for multiple languages to cater to a global audience.
    - **Integration with Other Services:** Explore integration with other AWS services or third-party tools for extended functionality.

## Contributing

We welcome contributions to this project! To ensure a smooth process, please adhere to the following guidelines:

1. **Fork the Repository:** Begin by creating your own fork of the repository on GitHub.
2. **Create a Branch:** Work on new features or fixes in a dedicated branch. Naming conventions for branches should be descriptive and relevant (e.g., `feature/new-ui` or `bugfix/fix-auth`).
3. **Implement Changes:** Make your changes or additions and run tests to ensure that they pass and do not break existing functionality.
4. **Commit and Push:** Commit your changes with clear, descriptive commit messages. Push your branch to your forked repository.
5. **Submit a Pull Request:** Open a pull request (PR) against the `main` branch of the original repository. Provide a detailed description of the changes made, including any relevant issue numbers and context.

For more detailed contributing instructions, please refer to our [CONTRIBUTING.md](https://github.com/MaheshShukla1/CONTRIBUTING.md). If you have any questions, feel free to contact Mahesh Shukla at MaheshCloudSec1@gmail.com.

## License

This project is licensed under the [MIT License](LICENSE). See the LICENSE file for more details.

## Contact

For any questions, feedback, or additional information, please reach out to Mahesh Shukla at MaheshCloudSec1@gmail.com.

## Acknowledgements

We would like to acknowledge the following resources that have contributed to the development of this project:

- [boto3](https://github.com/boto/boto3): AWS SDK for Python.
- [tkinter](https://docs.python.org/3/library/tkinter.html): Standard Python interface to the Tk GUI toolkit.

## FAQ

**Q: How do I update the AWS credentials?**

A: You can update your AWS credentials by using the command `aws configure`. This command will prompt you to enter your AWS Access Key ID, Secret Access Key, region, and output format.

## Support

For support, please open an issue on our [GitHub Issues](https://github.com/MaheshShukla1/repository/issues) page. Alternatively, you can contact Mahesh Shukla directly via email at MaheshCloudSec1@gmail.com for more personalized assistance.
