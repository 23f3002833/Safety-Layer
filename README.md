# Deploy on Render
1. Push this folder to a GitHub repo (app.py, requirements.txt, render.yaml, .python-version).
2. Render dashboard -> New -> Web Service -> pick the repo.
   Build: pip install -r requirements.txt
   Start: gunicorn -w 2 -b 0.0.0.0:$PORT app:app
3. Your endpoint: https://<your-service>.onrender.com/classify
4. Free tier sleeps: open the base URL in a browser to wake it before Check.
5. After the first Check, read Render Logs for "BATCH_SAMPLE" to see real field names and tune the regexes.
