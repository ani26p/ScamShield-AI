# ScamShield AG — Phishing Detection System

> AI-powered real-time phishing URL detection — Browser Extension + FastAPI Backend + Web Dashboard

---

## 📂 Project Structure

```
ScamShield AG/
├── backend/
│   ├── main.py              ← FastAPI app (POST /analyze)
│   └── requirements.txt
├── extension/
│   ├── manifest.json        ← Chrome MV3
│   ├── popup.html / .css / .js
│   ├── background.js
│   └── icons/               ← Auto-generated PNGs
├── frontend/
│   ├── index.html           ← Web dashboard
│   ├── style.css
│   └── app.js
├── models/
│   ├── model.pkl            ← Trained Voting Ensemble (99.75% F1)
│   └── feature_names.pkl
├── train_pipeline.py        ← ML training pipeline
├── generate_icons.py        ← One-time icon generator
└── start_backend.bat        ← Windows launcher
```

---

## 🚀 How to Run

### Step 1 — Install dependencies (one time)
```bash
pip install fastapi uvicorn pydantic joblib scikit-learn xgboost numpy
```

### Step 2 — Start the Backend
**Option A:** Double-click `start_backend.bat`

**Option B:** In terminal:
```bash
cd backend
uvicorn main:app --reload --port 8000
```

API will be running at: **http://localhost:8000**
Interactive docs: **http://localhost:8000/docs**

---

### Step 3 — Open the Dashboard
Serve the `frontend/` folder with **VS Code Live Server** (port 5500):
1. Open `frontend/index.html` in VS Code
2. Click **"Go Live"** in the bottom-right
3. Dashboard opens at `http://127.0.0.1:5500/frontend/index.html`

> You can also test the dashboard directly: `http://127.0.0.1:5500/frontend/index.html?url=https://google.com`

---

### Step 4 — Load the Chrome Extension
1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `extension/` folder
5. ScamShield icon appears in toolbar ✓

---

## 🔌 API Reference

### `GET /health`
```json
{ "status": "ok", "model": "Voting Ensemble", "features": [...] }
```

### `POST /analyze`
**Request:**
```json
{ "url": "https://example.com" }
```
**Response:**
```json
{
  "url": "https://example.com",
  "is_safe": true,
  "score": 82,
  "confidence": 0.9982,
  "phish_probability": 0.0018,
  "safe_probability": 0.9982,
  "model_used": "Voting Ensemble",
  "response_time_ms": 12.4,
  "features": { ... },
  "feature_analysis": { ... }
}
```

---

## 🧠 ML Model

| Model | Accuracy | F1 Score |
|---|---|---|
| Logistic Regression | 95.8% | 97.17% |
| Random Forest | 99.62% | 99.75% |
| XGBoost | 99.58% | 99.73% |
| **Voting Ensemble ★** | **99.62%** | **99.75%** |

**Features used:** URL Length · Dot Count · @ Symbol · Hyphen · Suspicious Keywords · URL Entropy · IP Address · Domain Length · HTTPS

---

## ⚠️ Notes
- Backend must be running on **port 8000** for the extension and dashboard to work
- Frontend must be served at **port 5500** (VS Code Live Server) for the extension's "View Report" link to open correctly
- To change ports, update `API` in `extension/popup.js` and `DASHBOARD_BASE`, and `API_BASE` in `frontend/app.js`
