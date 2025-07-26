import sys
import os
import certifi
from dotenv import load_dotenv
import pymongo
import logging
import pandas as pd
from uvicorn import run as app_run

from fastapi import FastAPI, Request, Form
from fastapi.responses import Response, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse

# Assuming your project structure is correct
from networksecurity.exception import exception
from networksecurity.pipeline.training_pipeline import TrainingPipeline
from networksecurity.utils.main_utils.utils import load_object
from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME, DATA_INGESTION_DATABASE_NAME
from networksecurity.utils.ml_utils.model.estimator import NetworkModel

# Correctly import your feature extraction class
from networksecurity.utils.feature_extraction import WebsiteFeatureExtractor 

# Initialize templates
templates = Jinja2Templates(directory="./templates")

# MongoDB setup
ca = certifi.where()
load_dotenv()
mongo_db_url = os.getenv("MONGO_DB_URL")
client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)
database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

app = FastAPI()
port = int(os.environ.get("PORT", 10000))
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

@app.get("/", tags=["authentication"], response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/train")
async def train_route():
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise exception.NetworkSecurityException(e, sys)
    
@app.get("/analyze", response_class=HTMLResponse)
async def analyze_form(request: Request):
    return templates.TemplateResponse("analyze.html", {"request": request})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_website(request: Request, website_url: str = Form(...)):
    try:
        # Initialize feature extractor
        extractor = WebsiteFeatureExtractor(website_url)
        
        # Extract all features with one simple call
        features = extractor.extract_features()
        
        # Convert to DataFrame for prediction
        # The keys in the 'features' dict now correctly match the model's expected columns
        df = pd.DataFrame([features])
        
        # Load model and make prediction
        # Ensure these paths are correct relative to where you run the app
        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=final_model)
        
        y_pred = network_model.predict(df)
        prediction = "Safe" if y_pred[0] == 0 else "Phishing"
        
        # Prepare results for display
        results = {
            "website_url": website_url,
            "prediction": prediction,
            "confidence": "High",  # Placeholder for confidence score
            "features": features
        }
        
        return templates.TemplateResponse("results.html", {
            "request": request,
            "results": results
        })
        
    except Exception as e:
        logging.error(f"An error occurred during analysis: {e}")
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e)
        })

if __name__ == "__main__":
    app_run(app, host='0.0.0.0', port=port)