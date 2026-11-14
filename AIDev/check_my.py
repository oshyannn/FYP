import pandas as pd
d = pd.read_csv("data/dataset_own.csv")
m = d.url.str.contains(r"^https?://[^/]*\.my(?:/|$)")
print(d[m].groupby(["label", "source"]).size())
