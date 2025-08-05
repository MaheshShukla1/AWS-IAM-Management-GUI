from PyQt5.QtWidgets import (
    QPushButton, QMessageBox,
    QHBoxLayout, QDialog, QFormLayout, QLineEdit,
)
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