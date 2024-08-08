# IAM Automation GUI

![Build Status](https://img.shields.io/github/workflow/status/MaheshShukla1/IAM-Automation-GUI/CI)
![License](https://img.shields.io/github/license/MaheshShukla1/IAM-Automation-GUI)
![Version](https://img.shields.io/github/release/MaheshShukla1/IAM-Automation-GUI)

**IAM Automation GUI** is a graphical user interface (GUI) tool designed for managing AWS Identity and Access Management (IAM) resources. This application allows users to create, list, and delete IAM users, roles, and policies, as well as manage their associated permissions. It is built using Python's `boto3` library and `tkinter` for the graphical interface, providing an intuitive and user-friendly way to handle IAM tasks.

## Table of Contents

- [Project Overview](#project-overview)
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

## Project Overview

IAM Automation GUI simplifies the process of managing AWS IAM resources by providing a desktop application with the following capabilities:

- **User Management**: Create, list, and delete IAM users.
- **Role Management**: Create, list, delete, attach policies to, and detach policies from IAM roles.
- **Policy Management**: Create, list, and delete IAM policies.
- **Group Management**: Create and delete IAM groups.
- **Logging**: Detailed logging of all actions performed within the application.

## Features

- **Graphical User Interface (GUI)**: Intuitive interface for easy management of IAM resources.
- **Logging**: Real-time logging of operations for better monitoring and troubleshooting.
- **Error Handling**: Informative error messages and validation checks to ensure correct operation.
- **Cross-platform**: Runs on any platform that supports Python and Tkinter.

## Installation

### Prerequisites

Ensure you have Python 3.x installed on your system. You'll also need to install the `boto3` and `tkinter` libraries.

### Installing Dependencies

1. Clone the repository:

    ```bash
    git clone https://github.com/MaheshShukla1/IAM-Automation-GUI.git
    cd IAM-Automation-GUI
    ```

2. Install the required Python packages:

    ```bash
    pip install boto3
    ```

    _Note: `tkinter` is included with Python, so no additional installation is usually required._

## Usage

1. **Configure AWS Credentials**: Ensure your AWS credentials are configured properly. You can set them up using the AWS CLI:

    ```bash
    aws configure
    ```

2. **Run the Application**:

    ```bash
    python app.py
    ```

3. **Using the GUI**:

    - **Create User**: Click "Create User" and enter the username to create a new IAM user.
    - **List Users**: Click "List Users" to view all existing IAM users.
    - **Delete User**: Click "Delete User" and enter the username to remove an IAM user.
    - **Create Role**: Click "Create Role" and enter the role name and trust policy JSON.
    - **Delete Role**: Click "Delete Role" and enter the role name to remove an IAM role.
    - **Attach Policy to Role**: Click "Attach Policy to Role" and provide the role name and policy ARN.
    - **Detach Policy from Role**: Click "Detach Policy from Role" and provide the role name and policy ARN.
    - **Create Policy**: Click "Create Policy" and provide the policy name and policy document JSON.
    - **List Policies**: Click "List Policies" to view all existing IAM policies.
    - **Delete Policy**: Click "Delete Policy" and enter the policy name to remove an IAM policy.
    - **Create Group**: Click "Create Group" to create a new IAM group.
    - **Delete Group**: Click "Delete Group" to remove an IAM group.

## Configuration

Customize the `app.py` file to adjust IAM operations based on your specific needs. Ensure AWS credentials and permissions are properly configured for the application to function correctly.

## Detailed Examples

### Example 1: Basic User Management

```python
# Create an IAM user using the IAM Automation GUI
# Go to "Create User", enter the username "test-user", and click "Create"
```
### Example 2: Role Management with Policy Attachment

```python
# Create a new role and attach a policy using the GUI
# Go to "Create Role", enter "test-role" and the trust policy JSON
# Then, navigate to "Attach Policy to Role", enter "test-role" and the policy ARN
```


## Troubleshooting

**Q: The application is not starting.**

A: Ensure that you have Python 3.x installed and that all dependencies are properly installed. Check if `boto3` and `tkinter` are correctly set up.

**Q: AWS credentials are not working.**

A: Verify that your AWS credentials are correctly configured using the `aws configure` command. Ensure that you have the necessary permissions to perform IAM operations.

## Roadmap

- **Future Enhancements**:
    - Implement additional IAM features (e.g., user groups management, policy attachments).
    - Improve the GUI with more advanced functionalities.
    - Enhance logging and error handling capabilities.

## Contributing

We appreciate your interest in contributing to IAM Automation GUI! To ensure a smooth contribution process, please adhere to the following guidelines:
	
1. **Fork the Repository**: Create your own copy of the repository on GitHub.
2. **Create a Branch**: Develop your feature or fix in a new branch. Use a descriptive name, e.g., `feature/add-logging` or `bugfix/issue-123`.
	    
	  ```bash
	    git checkout -b your-branch-name
	  ```
3. **Make Your Changes**: Implement your changes and ensure all new and existing tests pass. Follow our coding standards and add any necessary documentation.
4. **Commit and Push**: Commit your changes with a clear and concise message explaining the purpose of the changes. Push your branch to your forked repository.
	    
     ```bash
	    git commit -m "Your detailed commit message" git push origin your-branch-name
	 ```
5. **Submit a Pull Request**: Open a pull request against the `main` branch of the original repository. Include a detailed description of your changes, and reference any related issues.
6. **Review and Feedback**: Be open to feedback and make any necessary revisions based on the review. Engage in the discussion to refine your contribution.
	
For comprehensive contributing instructions, please refer to our [CONTRIBUTING.md](https://github.com/MaheshShukla1/CONTRIBUTING.md). If you have any questions, feel free to contact Mahesh Shukla at MaheshCloudSec1@gmail.com.


## License

This project is licensed under the [MIT License](LICENSE).

## Contact

For any questions or feedback, please reach out to Mahesh Shukla.
