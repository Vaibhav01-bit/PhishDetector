import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
import pickle

data = pd.read_csv("DataFiles/phishing.csv")
data = data.drop(['Index'], axis=1)
y = data['class']
X = data.drop('class', axis=1)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
gbc = GradientBoostingClassifier(max_depth=4, learning_rate=0.7)
gbc.fit(X_train, y_train)
pickle.dump(gbc, open('newmodel.pkl', 'wb'))
