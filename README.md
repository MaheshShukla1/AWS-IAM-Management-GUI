# AWS IAM Management GUI

![License](https://img.shields.io/github/license/MaheshShukla1/AWS-IAM-Management-GUI)

**AWS IAM Management GUI** is a cutting-edge desktop application crafted for streamlined **AWS IAM Management**. This sophisticated tool simplifies **AWS Identity and Access Management** tasks by providing an intuitive graphical user interface. Designed for efficiency, the **AWS IAM Management GUI** empowers users to effortlessly manage **IAM Users**, **IAM Roles**, **IAM Policies**, and **IAM Groups**. Built with Python’s robust `boto3` library and `tkinter` framework, it offers seamless integration with AWS services and enhances administrative capabilities with a user-friendly experience.
## 🚀 Introduction Video

Watch this video to see **AWS IAM Management GUI** in action and learn how to effectively use its features:


In this video, we demonstrate how to:

- Create and manage IAM users
- Assign and detach IAM roles
- Handle IAM policies and groups


## Prerequisites

1. **Python 3.x**: Ensure Python 3.x is installed. Tkinter comes with Python by default.
2. **AWS Credentials**: Configure AWS credentials using the AWS CLI or environment variables.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/MaheshShukla1/AWS-IAM-Management-GUI.git
cd AWS-IAM-Management-GUI
```

### 2. Install Dependencies

```bash
pip install boto3
```

### 3. Configure AWS Credentials
Set up your AWS credentials using:


```bash
aws configure
```

## Usage

1. **Run the Application**
    ```bash  
    python main.py
    ```
    
2. **Navigate the GUI**
    
    - **Create User**: Click "Create User" and enter the username.
    - **List Users**: Click "List Users" to view all IAM users.
    - **Delete User**: Click "Delete User" and confirm.
    - **Create Role**: Enter role details and trust policy JSON.
    - **Attach/Detach Policy**: Manage role policies by entering role name and policy ARN.
    - **Manage Policies**: Create, list, and delete IAM policies.
    - **Manage Groups**: Create and delete IAM groups

## Configuration

Customize `main.py` to suit specific needs. Ensure AWS credentials have the necessary permissions for desired operations.

## Troubleshooting

- **Application Not Starting**: Verify Python installation and dependencies. Ensure `boto3` and `tkinter` are properly installed.
- **AWS Credentials Issues**: Reconfigure using `aws configure` and verify credentials and permissions.
- **ClientError**: Check API usage limits and network connectivity.

## Roadmap

- **Extended Features**: Add user groups management, advanced policy management.
- **Enhanced GUI**: Improve UI with customizable views and user experience enhancements.
- **Logging & Error Handling**: Implement advanced logging and automated testing.
- **Performance Optimization**: Enhance performance with better thread and resource management.
- **Documentation & Support**: Develop comprehensive user and developer documentation.
- **Security Enhancements**: Incorporate secure authentication and data protection measures.
- **Feature Expansion**: Support for multiple languages and additional AWS services.

## Contributing

1. **Fork the Repository**: Create a fork on GitHub.
2. **Create a Branch**: Develop features or fixes in a new branch.
3. **Implement Changes**: Make updates and run tests.
4. **Submit a Pull Request**: Open a PR with a detailed description of changes.

For detailed contributing guidelines, refer to [CONTRIBUTING.md](https://github.com/MaheshShukla1/CONTRIBUTING.md). Contact Mahesh Shukla at MaheshCloudSec1@gmail.com for queries.

## License

This project is licensed under the MIT License.

## Contact

For support or inquiries, reach out to Mahesh Shukla at MaheshCloudSec1@gmail.com.

## Acknowledgements

- [boto3](https://github.com/boto/boto3) - AWS SDK for Python.
- [tkinter](https://docs.python.org/3/library/tkinter.html) - Python GUI toolkit.

## FAQ

**How do I update AWS credentials?**

Use the command `aws configure` to update your AWS credentials.

## Support

For issues, open a ticket on [GitHub Issues](https://github.com/MaheshShukla1/AWS-IAM-Management-GUI/issues) or email Mahesh Shukla at MaheshCloudSec1@gmail.com.
