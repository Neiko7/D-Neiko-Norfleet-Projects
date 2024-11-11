import os
import socket
import threading
import logging
import json
import datetime
from api_key_management import load_api_keys
from sklearn.ensemble import IsolationForest
import joblib
import pandas as pd
import tkinter as tk  # Importing tkinter for the GUI
from tkinter import simpledialog  # Importing simpledialog for input prompts

# Set the environment variable for TensorFlow if used in future
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Configure logging
logging.basicConfig(filename='logs/neinos.log', 
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Retrieve the Red and Blue Team passwords from environment variables
red_team_password = os.getenv("RED_TEAM_PASSWORD")
blue_team_password = os.getenv("BLUE_TEAM_PASSWORD")

# Example usage in authentication logic
def authenticate_team(team, password):
    if team == "red" and password == red_team_password:
        print("Red Team access granted.")
    elif team == "blue" and password == blue_team_password:
        print("Blue Team access granted.")
    else:
        print("Authentication failed.")

# Example usage
authenticate_team("red", "your_input_password")  # Replace with actual input password in use

class DataAccessLayer:
    @staticmethod
    def load_company_info():
        try:
            config_file = 'config.json'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    company_data = json.load(f)
                    company_name = company_data.get('company_name', 'Unknown Company')
                    company_address = company_data.get('company_address', 'Unknown Address')
                    contact_email = company_data.get('contact_email', 'contact@example.com')
                    contact_phone = company_data.get('contact_phone', '+1234567890')
                    return company_name, company_address, contact_email, contact_phone
            else:
                raise FileNotFoundError("Configuration file not found.")
        except Exception as e:
            logging.error(f"Error loading company information: {e}")
            exit()


class SecurityMonitoring:
    def __init__(self):
        self.isolation_forest = self.load_model()

    def load_model(self):
        try:
            model_path = 'models/anomaly_detection_model.pkl'
            if os.path.exists(model_path):
                return joblib.load(model_path)
            else:
                raise FileNotFoundError("ML Model for anomaly detection not found.")
        except Exception as e:
            logging.error(f"Error loading ML model: {e}")
            return None

    def detect_anomalies(self, log_data):
        try:
            prediction = self.isolation_forest.predict(log_data)
            if prediction == -1:
                logging.warning("Anomaly detected!")
                return True
            return False
        except Exception as e:
            logging.error(f"Error in anomaly detection: {e}")
            return False

    def update_model(self, new_data):
        try:
            # Update the anomaly detection model with new data
            df = pd.read_csv(new_data)
            X_train = df.values
            self.isolation_forest.fit(X_train)
            joblib.dump(self.isolation_forest, 'models/anomaly_detection_model.pkl')
            logging.info("Model updated with new data")
        except Exception as e:
            logging.error(f"Error updating model: {e}")


class BusinessLogicLayer:
    def __init__(self, company_info, api_keys):
        self.company_info = company_info
        self.api_keys = api_keys
        self.monitoring = SecurityMonitoring()

        # Team Sockets
        self.red_team_socket = self.setup_socket(12345)
        self.blue_team_socket = self.setup_socket(54321)

        # Connections
        self.red_team_connections = []
        self.blue_team_connections = []

        # Listening threads
        threading.Thread(target=self.listen_red_team).start()
        threading.Thread(target=self.listen_blue_team).start()

    def setup_socket(self, port):
        try:
            team_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            private_ip = socket.gethostbyname(socket.gethostname())
            team_socket.bind((private_ip, port))
            return team_socket
        except Exception as e:
            logging.error(f"Error setting up socket: {e}")
            return None

    def authenticate_client(self, api_key, team):
        if api_key == self.api_keys.get(team):
            return True
        logging.warning(f"Authentication failed for {team} Team.")
        return False

    def listen_red_team(self):
        self.red_team_socket.listen(5)
        while True:
            connection, address = self.red_team_socket.accept()
            self.red_team_connections.append(connection)
            self.handle_team_request(connection, address, "Red")

    def listen_blue_team(self):
        self.blue_team_socket.listen(5)
        while True:
            connection, address = self.blue_team_socket.accept()
            self.blue_team_connections.append(connection)
            self.handle_team_request(connection, address, "Blue")

    def handle_team_request(self, connection, address, team):
        api_key = connection.recv(1024).decode()
        if self.authenticate_client(api_key, team):
            if team == "Red":
                self.perform_red_team_tasks(address)
            elif team == "Blue":
                self.perform_blue_team_tasks(address)

    def perform_red_team_tasks(self, address):
        logging.info(f"Red Team task initiated from {address}")
        # Simulate task
        logging.info("Red Team successfully simulated an insider attack.")

    def perform_blue_team_tasks(self, address):
        logging.info(f"Blue Team task initiated from {address}")
        # Simulate task
        logging.info("Blue Team successfully defended against a simulated attack.")


class HomeScreen(tk.Tk):
    def __init__(self, business_logic):
        super().__init__()
        self.business_logic = business_logic
        self.title("NEINOS - Security Monitoring")

        tk.Label(self, text="NEINOS AI").pack(pady=10)
        tk.Button(self, text="Red Team Connect", command=self.connect_red_team).pack(pady=5)
        tk.Button(self, text="Blue Team Connect", command=self.connect_blue_team).pack(pady=5)
        tk.Button(self, text="View Reports", command=self.view_reports).pack(pady=5)

    def connect_red_team(self):
        api_key = simpledialog.askstring("API Key", "Enter Red Team API Key:")
        if api_key:
            self.business_logic.authenticate_client(api_key, "Red")

    def connect_blue_team(self):
        api_key = simpledialog.askstring("API Key", "Enter Blue Team API Key:")
        if api_key:
            self.business_logic.authenticate_client(api_key, "Blue")

    def view_reports(self):
        # Display recent security logs
        pass


# Main execution
if __name__ == "__main__":
    company_name, company_address, contact_email, contact_phone = DataAccessLayer.load_company_info()
    api_keys = load_api_keys()
    business_logic = BusinessLogicLayer((company_name, company_address, contact_email, contact_phone), api_keys)

    home_screen = HomeScreen(business_logic)
    home_screen.mainloop()
