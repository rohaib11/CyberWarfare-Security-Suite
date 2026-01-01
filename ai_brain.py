import numpy as np
from sklearn.ensemble import IsolationForest
import pandas as pd
import warnings
import joblib
import os

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)

BRAIN_FILE = "ai_memory.pkl"

class AIEngine:
    def __init__(self):
        # 1. Initialize the Model
        self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.data_buffer = []
        self.is_trained = False
        self.training_size = 20 # Samples needed to learn
        
        # 2. Try to Load Memory
        self.load_brain()

    def add_data_point(self, cpu, ram, disk_read, disk_write):
        """Adds data. If not trained, collects data. If trained, updates strictly."""
        # Only collect data for retraining if we haven't trained yet
        if not self.is_trained:
            self.data_buffer.append([cpu, ram, disk_read, disk_write])

            if len(self.data_buffer) >= self.training_size:
                self.train_model()

    def train_model(self):
        """Teaches the AI and SAVES the brain."""
        print("🧠 AI: Learning patterns...")
        df = pd.DataFrame(self.data_buffer, columns=['cpu', 'ram', 'read', 'write'])
        self.model.fit(df)
        self.is_trained = True
        
        # SAVE THE BRAIN TO DISK
        joblib.dump(self.model, BRAIN_FILE)
        print(f"🧠 AI: Knowledge saved to {BRAIN_FILE}")

    def predict_anomaly(self, cpu, ram, disk_read, disk_write):
        """Predicts using the loaded memory."""
        if not self.is_trained:
            return "LEARNING"
        
        data_point = pd.DataFrame([[cpu, ram, disk_read, disk_write]], 
                                  columns=['cpu', 'ram', 'read', 'write'])
        
        prediction = self.model.predict(data_point)
        
        if prediction[0] == -1:
            return "ANOMALY"
        else:
            return "NORMAL"

    def load_brain(self):
        """Loads the saved brain file if it exists."""
        if os.path.exists(BRAIN_FILE):
            try:
                self.model = joblib.load(BRAIN_FILE)
                self.is_trained = True
                print("🧠 AI: Memory loaded successfully from disk.")
            except:
                print("🧠 AI: Corrupt memory file. Starting fresh.")