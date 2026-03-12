import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import sys

print("Python version:", sys.version)
try:
    data = pd.read_csv("DataFiles/phishing.csv")
    print("Data loaded, shape:", data.shape)
    data = data.drop(['Index'], axis=1)
    y = data['class']
    X = data.drop('class', axis=1)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)
    
    # Small forest for diagnostics
    print("Starting small RF training...")
    rfc = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
    rfc.fit(X_train, y_train)
    print("Training successful!")
    
    pickle.dump(rfc, open('test_model.pkl', 'wb'))
    print("Model saved to test_model.pkl")
except Exception as e:
    print("Error:", e)
