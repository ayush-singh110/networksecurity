import yaml
from networksecurity.exception import exception
import logging
import os
import sys
import numpy as np
import dill
import pickle
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import r2_score
import sys
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import f1_score  # Use a classification metric
from networksecurity.exception.exception import NetworkSecurityException # Use your project's exception

def read_yaml_file(file_path: str)->dict:
    try:
        with open(file_path,'rb') as yaml_file:
            return yaml.safe_load(yaml_file)
    except Exception as e:
        raise exception.NetworkSecurityException(e, sys) 
    
def write_yaml_file(file_path: str, content: object, replace: bool=False)->None:
    try:
        if replace:
            if os.path.exists(file_path):
                os.remove(file_path)
        os.makedirs(os.path.dirname(file_path),exist_ok=True)
        with open(file_path,"w") as file:
            yaml.dump(content,file)
    except Exception as e:
        raise exception.NetworkSecurityException(e, sys)
    
def save_numpy_array_data(file_path: str,array:np.array):
    try:
        dir_path=os.path.dirname(file_path)
        os.makedirs(dir_path,exist_ok=True)
        with open(file_path,'wb') as file_obj:
            np.save(file_obj,array)
    except Exception as e:
        raise exception.NetworkSecurityException(e, sys)
    
def save_object(file_path: str,obj:object)->None:
    try:
        logging.info('Entered the save_object method of MainUtils class')
        os.makedirs(os.path.dirname(file_path),exist_ok=True)
        with open(file_path,'wb') as file_obj:
            pickle.dump(obj,file_obj)
        logging.info('Exited the save_object method od MainUtils class')
    except Exception as e:
        raise exception.NetworkSecurityException(e,sys)
    
def load_object(file_path: str)->object:
    try:
        if not os.path.exists(file_path):
            raise Exception(f"The file :{file_path} is not exists")
        with open(file_path,"rb") as file_obj:
            print(file_obj)
            return pickle.load(file_obj)
    except Exception as e:
        raise exception.NetworkSecurityException(e,sys)
    
def load_numpy_array_data(file_path: str)->np.array:
    """
    load numpy array data from file
    file_path: str location of file to load
    return: np.array data loaded
    """
    try:
        with open(file_path,"rb") as file_obj:
            return np.load(file_obj)
    except Exception as e:
        raise exception.NetworkSecurityException(e,sys)
    
# This is the code for your utils.py file



def evaluate_models(X_train, y_train, X_test, y_test, models, param):
    """
    This function performs hyperparameter tuning for given models and returns
    a report of their scores and the best estimator objects.
    """
    try:
        model_report = {}
        best_estimators = {}

        for model_name, model in models.items():
            # Get the parameters for the current model
            params = param[model_name]

            # Initialize GridSearchCV
            gs = GridSearchCV(model, params, cv=3)
            gs.fit(X_train, y_train)

            # Set the model to the best estimator found by the grid search
            best_model = gs.best_estimator_
            
            # Evaluate the best model on the test set
            y_test_pred = best_model.predict(X_test)
            
            # Use f1_score for classification
            test_model_score = f1_score(y_test, y_test_pred)

            # Store the score and the best model object
            model_report[model_name] = test_model_score
            best_estimators[model_name] = best_model

        # Return both dictionaries after the loop is done
        return model_report, best_estimators

    except Exception as e:
        raise NetworkSecurityException(e, sys)