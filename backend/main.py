import logging
import math
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .predictor import ScamShieldPredictor

# ── FastAPI App ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)

app = FastAPI(
    title="ScamShield API",
    description="Real-time phishing URL detection powered by ML",
    version="1.0.0",
)

predictor = ScamShieldPredictor()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "service":   "ScamShield API",
        "version":   "2.0.0",
        "model":     predictor.model_name,
        "endpoints": ["/health", "/analyze"],
    }

@app.get("/health")
def health():
    return {"status": "ok", "model": predictor.model_name, "features": predictor.feature_names}

@app.post("/analyze")
def analyze(req: URLRequest):
    t_start = time.perf_counter()
    url = (req.url or "").strip()

    if not url:
        logging.warning("Empty URL in request")
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    try:
        result = predictor.analyze(url)
    except Exception as e:
        logging.exception("Model inference failed for URL: %s", url)
        raise HTTPException(status_code=500, detail=f"Model inference failed: {e}")

    result["response_time_ms"] = round((time.perf_counter() - t_start) * 1000, 2)

    # Final safety cleanup
    score = result.get("credibility_score")
    if score is None or not isinstance(score, (int, float)) or (isinstance(score, float) and math.isnan(score)):
        result["credibility_score"] = 0.0

    logging.info("API /analyze response for %s: %s", url, {
        "prediction": result.get("prediction"),
        "confidence": result.get("confidence"),
        "credibility_score": result.get("credibility_score"),
    })

    return result

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"detail": str(exc)})
