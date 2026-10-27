HOW TO USE (run everything from inside the backend folder, with .venv active)

1. Copy these files into backend/ (overwrite app.py and phishtank.py):
   app.py  detector.py  phishtank.py  common.py  features.py  feeds.py
   build_dataset.py  train.py  requirements.txt  lists/ (3 txt files)
   Create an empty folder called data/ if it does not exist.
   Delete: analyzer.py, database.py, requirements-old.txt

2. pip install -r requirements.txt

3. python feeds.py            (downloads Tranco + OpenPhish + URLhaus into data/)
   python build_dataset.py    (creates data/dataset.csv)
   python train.py            (creates model.joblib - read the false positive rate)

4. python app.py              (the extension talks to http://127.0.0.1:5000/analyze)

Your scripts moved into scripts/ (verify_fix.py etc.): run them from backend/ with
   python -m scripts.verify_fix
