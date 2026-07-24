FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Download model files from GitHub Release (excluded from repo due to size)
ADD https://github.com/aditivvs03/cyber-threat-detection/releases/download/v1.0-models/random_forest.pkl models/random_forest.pkl
ADD https://github.com/aditivvs03/cyber-threat-detection/releases/download/v1.0-models/xgboost.pkl models/xgboost.pkl
ADD https://github.com/aditivvs03/cyber-threat-detection/releases/download/v1.0-models/shap_explainer.pkl models/shap_explainer.pkl

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]