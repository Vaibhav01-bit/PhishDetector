import pickle
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

try:
    with open('newmodel.pkl', 'rb') as f:
        model = pickle.load(f)
    print(f"Model type: {type(model)}")
    if hasattr(model, 'n_estimators'):
        print(f"n_estimators: {model.n_estimators}")
    if hasattr(model, 'max_depth'):
        print(f"max_depth: {model.max_depth}")
except Exception as e:
    print(f"Error: {e}")
