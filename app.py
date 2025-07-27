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

# Load environment variables first
load_dotenv()

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Assuming your project structure is correct
from networksecurity.exception import exception
from networksecurity.utils.main_utils.utils import load_object
from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME, DATA_INGESTION_DATABASE_NAME
from networksecurity.utils.ml_utils.model.estimator import NetworkModel

# Correctly import your feature extraction class
from networksecurity.utils.feature_extraction import WebsiteFeatureExtractor

# Conditional import for training pipeline
try:
    from networksecurity.pipeline.training_pipeline import TrainingPipeline
    TRAINING_AVAILABLE = True
    logger.info("Training pipeline imported successfully")
except ImportError as e:
    logger.warning(f"Training pipeline not available: {e}")
    TRAINING_AVAILABLE = False
except Exception as e:
    logger.warning(f"Training pipeline import failed: {e}")
    TRAINING_AVAILABLE = False

# Initialize templates
templates = Jinja2Templates(directory="./templates")

# MongoDB setup
ca = certifi.where()
mongo_db_url = os.getenv("MONGO_DB_URL")

# Initialize MongoDB client with error handling
try:
    if mongo_db_url:
        client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)
        database = client[DATA_INGESTION_DATABASE_NAME]
        collection = database[DATA_INGESTION_COLLECTION_NAME]
        logger.info("MongoDB connection established")
    else:
        logger.warning("MongoDB URL not provided")
        client = None
        database = None
        collection = None
except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
    client = None
    database = None
    collection = None

app = FastAPI(title="Network Security API", version="1.0.0")

# Get port from environment - Render provides this automatically
port = int(os.environ.get("PORT", 10000))
logger.info(f"Starting on port: {port}")

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
    try:
        return templates.TemplateResponse("index.html", {"request": request})
    except Exception as e:
        logger.error(f"Error rendering index page: {e}")
        return HTMLResponse("""
        <html>
            <body>
                <h1>Network Security API</h1>
                <p>API is running successfully!</p>
                <a href="/analyze">Analyze Website</a>
            </body>
        </html>
        """)

@app.get("/health")
async def health_check():
    """Health check endpoint for deployment monitoring"""
    return {
        "status": "healthy",
        "port": port,
        "training_available": TRAINING_AVAILABLE,
        "mongodb_connected": client is not None
    }

@app.get("/train")
async def train_route():
    if not TRAINING_AVAILABLE:
        return Response(
            "Training pipeline not available in this deployment environment", 
            status_code=503
        )
    
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise exception.NetworkSecurityException(e, sys)

@app.get("/analyze", response_class=HTMLResponse)
async def analyze_form(request: Request):
    try:
        return templates.TemplateResponse("analyze.html", {"request": request})
    except Exception as e:
        logger.error(f"Error rendering analyze page: {e}")
        return HTMLResponse("""
        <html>
            <body>
                <h1>Website Analysis</h1>
                <form method="post" action="/analyze">
                    <label>Website URL:</label><br>
                    <input type="url" name="website_url" required style="width: 300px; padding: 5px;"><br><br>
                    <button type="submit" style="padding: 10px 20px;">Analyze</button>
                </form>
            </body>
        </html>
        """)

@app.post("/analyze", response_class=HTMLResponse)
async def analyze_website(request: Request, website_url: str = Form(...)):
    try:
        # Initialize feature extractor
        extractor = WebsiteFeatureExtractor(website_url)
        
        # Extract all features with one simple call
        features = extractor.extract_features()
        
        # Convert to DataFrame for prediction
        df = pd.DataFrame([features])
        
        # Load model and make prediction
        try:
            preprocessor = load_object("final_model/preprocessor.pkl")
            final_model = load_object("final_model/model.pkl")
            network_model = NetworkModel(preprocessor=preprocessor, model=final_model)
            
            y_pred = network_model.predict(df)
            prediction = "Safe" if y_pred[0] == 0 else "Phishing"
            
        except FileNotFoundError as e:
            logger.error(f"Model files not found: {e}")
            return HTMLResponse(f"""
            <html>
                <body>
                    <h1>Error</h1>
                    <p>Model files not found. Please ensure the model is trained and deployed.</p>
                    <p>Error: {str(e)}</p>
                    <a href="/analyze">Try Again</a>
                </body>
            </html>
            """)
        
        # Prepare results for display
        results = {
            "website_url": website_url,
            "prediction": prediction,
            "confidence": "High",  # Placeholder for confidence score
            "features": features
        }
        
        try:
            return templates.TemplateResponse("results.html", {
                "request": request,
                "results": results
            })
        except Exception as template_error:
            # Fallback HTML response if templates are not available
            feature_display = "<br>".join([f"<strong>{k}:</strong> {v}" for k, v in features.items()])
            return HTMLResponse(f"""
            <html>
                <body>
                    <h1>Analysis Results</h1>
                    <p><strong>Website:</strong> {website_url}</p>
                    <p><strong>Prediction:</strong> <span style="color: {'green' if prediction == 'Safe' else 'red'}; font-weight: bold;">{prediction}</span></p>
                    <p><strong>Confidence:</strong> High</p>
                    <h3>Features:</h3>
                    <div style="background: #f5f5f5; padding: 10px; margin: 10px 0;">
                        {feature_display}
                    </div>
                    <a href="/analyze">Analyze Another Website</a>
                </body>
            </html>
            """)
            
    except Exception as e:
        logger.error(f"An error occurred during analysis: {e}")
        return HTMLResponse(f"""
        <html>
            <body>
                <h1>Error</h1>
                <p>An error occurred during analysis: {str(e)}</p>
                <a href="/analyze">Try Again</a>
            </body>
        </html>
        """)

# Add a simple API endpoint for programmatic access
@app.post("/api/analyze")
async def api_analyze_website(website_url: str = Form(...)):
    """API endpoint for programmatic website analysis"""
    try:
        extractor = WebsiteFeatureExtractor(website_url)
        features = extractor.extract_features()
        df = pd.DataFrame([features])
        
        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=final_model)
        
        y_pred = network_model.predict(df)
        prediction = "Safe" if y_pred[0] == 0 else "Phishing"
        
        return {
            "website_url": website_url,
            "prediction": prediction,
            "confidence": "High",
            "features": features
        }
        
    except Exception as e:
        logger.error(f"API analysis error: {e}")
        return {"error": str(e)}, 500

if __name__ == "__main__":
    logger.info(f"Starting server on host 0.0.0.0 and port {port}")
    app_run(app, host='0.0.0.0', port=port)