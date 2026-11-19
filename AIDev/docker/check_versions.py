import json
import re
import urllib.request

tags = json.load(urllib.request.urlopen("https://mcr.microsoft.com/v2/playwright/python/tags/list"))["tags"]
found = {}
for t in tags:
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)-(jammy|noble)", t)
    if m:
        found.setdefault(tuple(map(int, m.groups()[:3])), []).append(m.group(4))
for v in sorted(found)[-8:]:
    print("v%d.%d.%d" % v, found[v])