# IAM Automation GUI

![Build Status](https://img.shields.io/github/workflow/status/MaheshShukla1/IAM-Automation-GUI/CI)
![License](https://img.shields.io/github/license/MaheshShukla1/IAM-Automation-GUI)
![Version](https://img.shields.io/github/release/MaheshShukla1/IAM-Automation-GUI)

**IAM Automation GUI** is a powerful tool designed to streamline the management of AWS Identity and Access Management (IAM) resources. With an intuitive graphical user interface (GUI), users can effortlessly create, list, and manage IAM users, roles, policies, and groups. Built with Python’s `boto3` library and `tkinter`, this application simplifies complex IAM tasks and enhances productivity.

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
- [Acknowledgements](#acknowledgements)
- [FAQ](#faq)
- [Support](#support)

## Project Overview

IAM Automation GUI simplifies AWS IAM management through a desktop application, offering:

- **User Management**: Effortlessly create, list, and delete IAM users.
- **Role Management**: Manage IAM roles by creating, listing, deleting, and attaching policies.
- **Policy Management**: Create, list, and delete IAM policies.
- **Group Management**: Manage IAM groups, including creation and deletion.
- **Logging**: Comprehensive logging of all actions for monitoring and troubleshooting.

## Features

- **User-Friendly GUI**: Easy-to-navigate interface for IAM operations.
- **Real-Time Logging**: Monitor all actions with detailed logs.
- **Error Handling**: Informative error messages and validation to ensure smooth operation.
- **Cross-Platform**: Compatible with all platforms supporting Python and Tkinter.

## Installation

### Prerequisites

Ensure Python 3.x is installed. Install the `boto3` library, and `tkinter` comes pre-installed with Python.

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

## Usage

1. **Configure AWS Credentials**: Set up your AWS credentials with:

    ```bash
    aws configure
    ```

2. **Run the Application**:

    ```bash
    python app.py
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

Customize `app.py` for your specific needs. Make sure your AWS credentials have the necessary permissions.

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

A: Ensure Python 3.x is installed and dependencies are correctly set up. Check `boto3` and `tkinter` installations.

**Q: AWS credentials are not working.**

A: Verify AWS credentials with `aws configure` and ensure proper permissions.

## Roadmap

- **Future Enhancements**:
    - Add more IAM features like user groups management.
    - Enhance GUI functionalities.
    - Improve logging and error handling.

## Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the Repository**: Create your own fork on GitHub.
2. **Create a Branch**: Develop features or fixes in a new branch.
3. **Make Changes**: Implement changes and ensure tests pass.
4. **Commit and Push**: Commit your changes and push to your forked repo.
5. **Submit a Pull Request**: Open a pull request with a detailed description.

For detailed contributing instructions, refer to our [CONTRIBUTING.md](https://github.com/MaheshShukla1/CONTRIBUTING.md). For queries, contact Mahesh Shukla at MaheshCloudSec1@gmail.com.

## License

This project is licensed under the [MIT License](LICENSE).

## Contact

For questions or feedback, reach out to Mahesh Shukla at MaheshCloudSec1@gmail.com.

## Acknowledgements

- [boto3](https://github.com/boto/boto3)
- [tkinter](https://docs.python.org/3/library/tkinter.html)

## FAQ

**Q: How do I update the AWS credentials?**

A: Use the `aws configure` command to update your credentials.

## Support

For support, please open an issue on GitHub or contact Mahesh Shukla directly.
