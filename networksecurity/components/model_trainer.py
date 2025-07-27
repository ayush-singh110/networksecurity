import os
import sys
import numpy as np

from networksecurity.exception import exception
import logging

from networksecurity.entity.artifact_entity import DataTransformationArtifact,ModelTrainerArtifact
from networksecurity.entity.config_entity import ModelTrainerConfig

from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.main_utils.utils import save_object,load_object
from networksecurity.utils.main_utils.utils import load_numpy_array_data,evaluate_models
from networksecurity.utils.ml_utils.metric.classification_metric import get_classification_score
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import r2_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    AdaBoostClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier
)
import mlflow
import joblib
import time

logger = logging.getLogger(__name__)

def initialize_dagshub():
    """Initialize DagHub only if authentication is available"""
    try:
        
        if (os.getenv('RENDER') or 
            os.getenv('HEROKU') or 
            os.getenv('RAILWAY_ENVIRONMENT') or 
            os.getenv('VERCEL') or
            os.getenv('NETLIFY')):
            logger.info("Deployment environment detected. Skipping DagHub initialization.")
            return False
            
        
        if os.getenv('DAGSHUB_TOKEN'):
            import dagshub
            dagshub.init(repo_owner='ayush-singh110', repo_name='networksecurity', mlflow=True)
            logger.info("DagHub initialized successfully with token")
            return True
            
       
        config_path = os.path.expanduser('~/.dagshub/config')
        if os.path.exists(config_path):
            import dagshub
            dagshub.init(repo_owner='ayush-singh110', repo_name='networksecurity', mlflow=True)
            logger.info("DagHub initialized successfully with config file")
            return True
            
        
        try:
            import dagshub
            dagshub.init(repo_owner='ayush-singh110', repo_name='networksecurity', mlflow=True)
            logger.info("DagHub initialized successfully")
            return True
        except:
            logger.info("No DagHub authentication found. Skipping initialization.")
            return False
        
    except Exception as e:
        logger.warning(f"DagHub initialization failed: {e}")
        logger.info("Continuing without DagHub integration...")
        return False


DAGSHUB_AVAILABLE = initialize_dagshub()

class ModelTrainer:
    def __init__(self,model_trainer_config:ModelTrainerConfig,data_transformation_artifact:DataTransformationArtifact):
        try:
            self.model_trainer_config=model_trainer_config
            self.data_transformation_artifact=data_transformation_artifact
        except Exception as e:
            raise exception.NetworkSecurityException(e,sys)
        
    def track_mlflow(self, best_model, classificationmetric):
        if not DAGSHUB_AVAILABLE:
            
            logger.info(f"F1 Score: {classificationmetric.f1_score}")
            logger.info(f"Precision: {classificationmetric.precision_score}")
            logger.info(f"Recall: {classificationmetric.recall_score}")
            return
            
        try:
            with mlflow.start_run():
                f1_score = classificationmetric.f1_score
                precision_score = classificationmetric.precision_score
                recall_score = classificationmetric.recall_score

                mlflow.log_metric("f1_score", f1_score)
                mlflow.log_metric("precision", precision_score)
                mlflow.log_metric("recall_score", recall_score)

                model_filename = f"model_{int(time.time())}.pkl"
                joblib.dump(best_model, model_filename)
                mlflow.log_artifact(model_filename)
                
                logger.info("Metrics logged to MLflow successfully")
        except Exception as e:
            logger.warning(f"Failed to log to MLflow: {e}")
            logger.info(f"F1 Score: {classificationmetric.f1_score}")
            logger.info(f"Precision: {classificationmetric.precision_score}")
            logger.info(f"Recall: {classificationmetric.recall_score}")
        
        
    def train_model(self,X_train,y_train,X_test,y_test):
        models={
            "Random Forest":RandomForestClassifier(verbose=1),
            "Decision Tree":DecisionTreeClassifier(),
            "Gradient Boosting":GradientBoostingClassifier(verbose=1),
            "Logistic Regression":LogisticRegression(verbose=1),
            "AdaBoost":AdaBoostClassifier()
        }
        param={
            "Decision Tree":{
                'criterion':['gini','entropy','log_loss'],

            },
            "Random Forest":{
                'n_estimators':[8,16,32,64,128,256]
            },
            "Gradient Boosting":{
                'learning_rate':[.1,.01,.05,.001],
                'subsample':[0.6,0.7,0.75,0.8,0.85,0.9],
                'n_estimators':[8,16,32,64,128,256]
            },
            "Logistic Regression":{},
            "AdaBoost":{
                'learning_rate':[.1,.01,0.5,.001],
                'n_estimators':[8,16,32,64,128,256]
            }
        }
        model_report, best_estimators = evaluate_models(X_train=X_train,y_train=y_train,X_test=X_test,y_test=y_test,models=models,param=param)
        best_model_score=max(sorted(model_report.values()))

        best_model_name=list(model_report.keys())[
            list(model_report.values()).index(best_model_score)
        ]
        best_model=best_estimators[best_model_name]
        y_train_pred=best_model.predict(X_train)
        classification_train_metric=get_classification_score(y_true=y_train,y_pred=y_train_pred)
        
        self.track_mlflow(best_model,classification_train_metric)

        y_test_pred=best_model.predict(X_test)
        classification_test_metric=get_classification_score(y_true=y_test,y_pred=y_test_pred)

        self.track_mlflow(best_model,classification_test_metric)

        preprocessor=load_object(file_path=self.data_transformation_artifact.transformed_object_file_path)
        model_dir_path=os.path.dirname(self.model_trainer_config.trained_model_file_path)
        os.makedirs(model_dir_path,exist_ok=True)
        Network_Model=NetworkModel(preprocessor=preprocessor,model=best_model)
        save_object(self.model_trainer_config.trained_model_file_path,obj=Network_Model)

        final_model_dir = "final_model"
        os.makedirs(final_model_dir, exist_ok=True)
        save_object(os.path.join(final_model_dir, "model.pkl"), best_model)
        
        save_object(os.path.join(final_model_dir, "preprocessor.pkl"), preprocessor)

        model_trainer_artifact=ModelTrainerArtifact(trained_model_file_path=self.model_trainer_config.trained_model_file_path,
                             train_metric_artifact=classification_train_metric,
                             test_metric_artifact=classification_test_metric)

        logging.info(f"Best model found on both train and test dataset is: {best_model_name} with score: {best_model_score}")
        return model_trainer_artifact
        
    def initiate_model_trainer(self)->ModelTrainerArtifact:
        try:
            train_file_path=self.data_transformation_artifact.transformed_train_file_path
            test_file_path=self.data_transformation_artifact.transformed_test_file_path

            train_arr=load_numpy_array_data(train_file_path)
            test_arr=load_numpy_array_data(test_file_path)
            X_train = train_arr[:, :-1]
            y_train = train_arr[:, -1]
            X_test = test_arr[:, :-1]
            y_test = test_arr[:, -1]
            
            model_trainer_artifact=self.train_model(X_train,y_train,X_test,y_test)
            return model_trainer_artifact

        except Exception as e:
            raise exception.NetworkSecurityException(e,sys)