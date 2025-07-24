import sys
import speedtest
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt5.QtGui import QFont


class SpeedTestApp(QWidget):
    def __init__(self):
        """Initializes the speed test application with UI elements."""
        super().__init__()
        self.init_ui()

    def init_ui(self):
        """Sets up the application window, layout, and styled widgets."""
        self.setWindowTitle("Network Speed Test")
        self.setGeometry(100, 100, 400, 300)

        # Apply custom font
        app_font = QFont("Arial", 12)
        self.setFont(app_font)

        # Set layout
        layout = QVBoxLayout()

        # Instruction label
        self.label = QLabel("Click 'Start Test' to measure your network speed.")
        self.label.setStyleSheet("color: #660000; font-size: 14px; font-weight: bold;")
        layout.addWidget(self.label)

        # Start button
        self.start_button = QPushButton("Start Test", self)
        self.start_button.setStyleSheet("""
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
        """)
        self.start_button.clicked.connect(self.run_speed_test)
        layout.addWidget(self.start_button)

        # Results label
        self.results_label = QLabel("")
        self.results_label.setStyleSheet("color: #003366; font-size: 14px;")
        layout.addWidget(self.results_label)

        # Apply layout
        self.setLayout(layout)

        # Apply overall window styling
        self.setStyleSheet("""
            QWidget {
                background-color: #f2f2f2;
            }
        """)

    def run_speed_test(self):
        """Runs the network speed test and updates UI with results in real-time."""
        self.label.setText("Testing... Please wait.")
        QApplication.processEvents()

        try:
            st = speedtest.Speedtest()
            # RUN speedtest-cli --list to get a list of valid servers
            st.get_servers([1234])  # Replace with a valid Speedtest server ID

            # TEST DOWNLOAD SPEED
            self.label.setText("Testing Download Speed...")
            QApplication.processEvents()
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            self.results_label.setText(f"Download Speed: {download_speed:.2f} Mbps\n")
            QApplication.processEvents()

            # TEST UPLOAD SPEED
            self.label.setText("Testing Upload Speed...")
            QApplication.processEvents()
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            self.results_label.setText(
                f"Download Speed: {download_speed:.2f} Mbps\n"
                f"Upload Speed: {upload_speed:.2f} Mbps\n"
            )
            QApplication.processEvents()

            # TEST PING
            self.label.setText("Testing Ping...")
            QApplication.processEvents()
            ping = st.results.ping
            self.results_label.setText(
                f"Download Speed: {download_speed:.2f} Mbps\n"
                f"Upload Speed: {upload_speed:.2f} Mbps\n"
                f"Ping: {ping:.2f} ms"
            )
            self.label.setText("Testing Complete!")
            QApplication.processEvents()

        except Exception as e:
            self.results_label.setText("Error: Could not complete the test.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SpeedTestApp()
    window.show()
    sys.exit(app.exec_())


