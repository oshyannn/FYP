Copy each file to the same path inside D:\Desktop\FYP\ (overwrite when it already exists):

AIDev\aidev\core\list_store.py                 (updated)  reads admin-approved threats from global_urls
AIDev\aidev\detection\detector.py              (updated)  admin-approved threats beat every whitelist; reload without restart
Backend\web\detector_sync.py                   (NEW)
Backend\web\db_models\system_lists.py          (NEW)
Backend\web\controllers\system_lists.py        (NEW)     admin: manage whitelist / not_trusted / blacklist / adult_manual
Backend\web\controllers\threats.py             (updated)  refresh the detector after approve / remove
Backend\web\controllers\submissions.py         (updated)  refresh the detector after approve / reject
Backend\web\web_setup.py                       (updated)  registers the new controller

Then restart the Backend (cd Backend ; python app.py).
