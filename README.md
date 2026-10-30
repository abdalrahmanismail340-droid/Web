# WebPwn — Web Vulnerability Scanner & Exploitation Toolkit

Full-fidelity web vulnerability scanner with exploitation capabilities.

## Deploy on Railway

1. Create a new project on [Railway](https://railway.app)
2. Deploy from GitHub repo **or** upload these files
3. Railway will detect the `Procfile` and `requirements.txt` automatically
4. Set the start command if needed:  
   `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --threads 4 --timeout 120`

### Required files
- `app.py` (main application)
- `requirements.txt`
- `Procfile`

That's all. No environment variables needed.

## Local run

```bash
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000
