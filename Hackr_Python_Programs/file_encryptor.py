import sys
import os
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QMessageBox, QLineEdit
from PyQt5.QtGui import QFont
from cryptography.fernet import Fernet


class FileEncryptor(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        """Initializes the UI layout and widgets with styling."""
        self.setWindowTitle("File Encryption & Decryption Tool")
        self.setGeometry(100, 100, 450, 300)
        
        # Apply custom font and layout
        app_font = QFont("Arial", 12)
        self.setFont(app_font)
        layout = QVBoxLayout()
        
        self.label = QLabel("Select a file to encrypt or decrypt.")
        self.label.setStyleSheet("color: #FF0000; font-size: 14px; font-weight: bold;")
        layout.addWidget(self.label)
        
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("""
            QLineEdit {
                border: 2px solid #FF0000;
                border-radius: 5px;
                padding: 5px;
                font-size: 14px;
            }
        """
        )
        layout.addWidget(self.password_input)
        
        self.select_button = QPushButton("Select File")
        self.select_button.setStyleSheet("""
            QPushButton {
                background-color: #FF0000;
                color: white;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #CC0000;
            }
        """
        )
        self.select_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_button)
        
        self.encrypt_button = QPushButton("Encrypt File")
        self.encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #008000;
                color: white;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #006600;
            }
        """
        )
        self.encrypt_button.clicked.connect(lambda: self.encrypt_file(self.file_path, self.password_input.text()) if hasattr(self, 'file_path') else None)
        layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Decrypt File")
        self.decrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #000080;
                color: white;
                border-radius: 5px;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #000066;
            }
        """
        )
        self.decrypt_button.clicked.connect(lambda: self.decrypt_file(self.file_path, self.password_input.text()) if hasattr(self, 'file_path') else None)
        layout.addWidget(self.decrypt_button)
        
        self.setLayout(layout)
        
        # Apply overall window styling
        self.setStyleSheet("""
            QWidget {
                background-color: #000000;
                color: white;
            }
        """
        )
    
    def select_file(self):
        """Opens a file dialog for selecting the file to encrypt or decrypt."""
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select File to Encrypt/Decrypt")
        
        if file_path:
            self.file_path = file_path
            self.label.setText(f"Selected: {os.path.basename(file_path)}")
    
    def encrypt_file(self, file_path, password):
        """Encrypts the selected file using AES encryption."""
        key = base64.urlsafe_b64encode(password.ljust(32).encode('utf-8'))
        cipher = Fernet(key)
        
        try:
            with open(file_path, "rb") as file:
                file_data = file.read()
            encrypted_data = cipher.encrypt(file_data)
            
            with open(file_path + ".enc", "wb") as file:
                file.write(encrypted_data)
            
            self.label.setText("File successfully encrypted!")
        except Exception as e:
            self.label.setText("Error: Encryption failed.")

    def decrypt_file(self, file_path, password):
        """Decrypts the selected file using AES decryption."""
        key = base64.urlsafe_b64encode(password.ljust(32).encode('utf-8'))
        cipher = Fernet(key)
        
        try:
            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            decrypted_data = cipher.decrypt(encrypted_data)
            
            new_file_path = file_path.replace(".enc", "")
            with open(new_file_path, "wb") as file:
                file.write(decrypted_data)
            
            self.label.setText("File successfully decrypted!")
        except Exception as e:
            self.label.setText("Error: Decryption failed.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileEncryptor()
    window.show()
    sys.exit(app.exec_())

