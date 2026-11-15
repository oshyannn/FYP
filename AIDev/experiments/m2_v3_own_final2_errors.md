# Error analysis experiments/m2_v3_own_final2_preds.csv

- threshold (raw probability, 1% false-positive rate on this test set): 0.8529
- test pages 1113: phishing 267, benign 846
- missed phishing pages (false negatives): 232 (86.9%)
- wrongly flagged benign pages (false positives): 8 (0.9%)

## Why phishing pages were missed (all of them)

| cause | pages | share |
|---|---|---|
| tiny page: almost no text to judge | 82 | 35.3% |
| on a shared hosting / link-shortener platform (the saved page may be the platform's own; domain with many phishing pages) | 65 | 28.0% |
| no form at all (landing / lure page) | 42 | 18.1% |
| has a form, nothing sensitive | 29 | 12.5% |
| redirector page (meta refresh or JavaScript redirect) | 11 | 4.7% |
| has a credential form but no other strong signal | 3 | 1.3% |

False negatives by source: phish_feed 232

## Are the catches coming from page length alone?

| group | phishing pages | phishing flagged | recall | benign pages | benign flagged | false-positive rate |
|---|---|---|---|---|---|---|
| tiny page (< 30 words) | 121 | 24 | 19.8% | 138 | 5 | 3.6% |
| readable page | 146 | 11 | 7.5% | 708 | 3 | 0.4% |

## Why benign pages were flagged (all of them)

| cause | pages | share |
|---|---|---|
| tiny page: almost no text to judge | 5 | 62.5% |
| mostly links / resources on other websites | 2 | 25.0% |
| no obvious cause (ordinary page) | 1 | 12.5% |

False positives by source: benign_tail 5, benign_tail_login 2, benign_top 1

## Random sample of missed phishing pages (URLs defanged: do NOT open)

| source | prob | url | cause | words | forms | password | ext link ratio |
|---|---|---|---|---|---|---|---|
| phish_feed | 0.23 | `hxxps://www[.]linkedin[.]com/slink?code=etjqs5cv` | has a credential form but no other strong signal | 754 | 2 | 1 | 0.01 |
| phish_feed | 0.582 | `hxxp://66[.]39[.]79[.]68/` | no form at all (landing / lure page) | 305 | 0 | 0 | 0.14 |
| phish_feed | 0.723 | `hxxps://vk[.]com/away[.]php?to=http://aza[.]scia-a-roma[.]it/conferma/web/login[.]php` | tiny page: almost no text to judge | 48 | 0 | 0 | 0.5 |
| phish_feed | 0.842 | `hxxps://1sh[.]co/e3c9dfb6#amvubnlabg5wlmnvlnvr` | tiny page: almost no text to judge | 34 | 0 | 0 | 0.0 |
| phish_feed | 0.479 | `hxxps://ee[.]kobotoolbox[.]org/x/hxh6atau` | redirector page (meta refresh or JavaScript redirect) | 89 | 0 | 0 | 0.0 |
| phish_feed | 0.555 | `hxxps://qrco[.]de/bfv8k9` | on a shared hosting / link-shortener platform (the saved page may be the platform's own; domain with many phishing pages) | 150 | 0 | 0 | 0.17 |
| phish_feed | 0.035 | `hxxps://qrco[.]de/bfvj3t` | on a shared hosting / link-shortener platform (the saved page may be the platform's own; domain with many phishing pages) | 1504 | 1 | 0 | 0.09 |
| phish_feed | 0.384 | `hxxps://4484471d[.]orson[.]website/?utm_source=activecampaign&utm_medium=email&utm_content=mislp&utm_campaign=nouvelle%20campagne%20%28copie%29%20%28copie%29` | no form at all (landing / lure page) | 163 | 0 | 0 | 0.39 |
| phish_feed | 0.702 | `hxxps://ezurl[.]nl/yloi2` | tiny page: almost no text to judge | 8 | 0 | 0 | 0.0 |
| phish_feed | 0.346 | `hxxps://iuparadas[.]org/` | has a form, nothing sensitive | 337 | 1 | 0 | 0.35 |
| phish_feed | 0.4 | `hxxps://careattmobile[.]surveysparrow[.]com/s/satisfaction-survey/tt-5n1qdnhmqwhxce4qclavce` | tiny page: almost no text to judge | 11 | 0 | 0 | 0.0 |
| phish_feed | 0.421 | `hxxps://surli[.]cc/gkmeeo` | has a form, nothing sensitive | 804 | 1 | 0 | 0.62 |
| phish_feed | 0.809 | `hxxps://serp[.]us-lax-1[.]linodeobjects[.]com/index[.]html` | tiny page: almost no text to judge | 13 | 1 | 1 | 0.0 |
| phish_feed | 0.758 | `hxxp://ahhhh[.]pe[.]kr/zb41/data/1057168297/?email=3mail@b[.]c` | has a credential form but no other strong signal | 570 | 3 | 1 | 0.0 |
| phish_feed | 0.425 | `hxxps://lnk[.]ink/ry9mt` | no form at all (landing / lure page) | 69 | 0 | 0 | 0.0 |
| phish_feed | 0.782 | `hxxp://www-degelyehuda-org-il[.]filesusr[.]com/html/87d61b_fe256cdcaf57de9f630e7e55861dee2f[.]html` | tiny page: almost no text to judge | 9 | 0 | 0 | 0.0 |
| phish_feed | 0.77 | `hxxp://minimesactivities[.]com/wz1#example@example[.]example` | tiny page: almost no text to judge | 8 | 0 | 0 | 0.0 |
| phish_feed | 0.35 | `hxxps://surl[.]li/hcancz` | has a form, nothing sensitive | 822 | 1 | 0 | 0.28 |
| phish_feed | 0.748 | `hxxps://l[.]ead[.]me/bgacpi` | on a shared hosting / link-shortener platform (the saved page may be the platform's own; domain with many phishing pages) | 4 | 0 | 0 | 0.0 |
| phish_feed | 0.224 | `hxxps://satarabazar[.]com/spe[.]php` | has a form, nothing sensitive | 450 | 2 | 0 | 0.04 |
| phish_feed | 0.702 | `hxxps://ezurl[.]nl/grtkb` | tiny page: almost no text to judge | 8 | 0 | 0 | 0.0 |
| phish_feed | 0.436 | `hxxps://selectiondulocker[.]com/` | tiny page: almost no text to judge | 23 | 0 | 0 | 0.17 |
| phish_feed | 0.292 | `hxxps://q-r[.]to/bften2` | on a shared hosting / link-shortener platform (the saved page may be the platform's own; domain with many phishing pages) | 800 | 1 | 0 | 0.22 |
| phish_feed | 0.809 | `hxxps://eyo[.]lqn[.]mybluehost[.]me/` | tiny page: almost no text to judge | 28 | 0 | 0 | 0.0 |
| phish_feed | 0.042 | `hxxps://qrco[.]de/bfkapi` | on a shared hosting / link-shortener platform (the saved page may be the platform's own; domain with many phishing pages) | 1331 | 0 | 0 | 0.08 |
| phish_feed | 0.557 | `hxxps://btemailaddress[.]plutio[.]com/p/form/kfxgoa85dx6skreyx` | tiny page: almost no text to judge | 10 | 0 | 0 | 0.0 |
| phish_feed | 0.562 | `hxxps://portaly[.]cc/btsyncservice` | tiny page: almost no text to judge | 17 | 0 | 0 | 0.0 |
| phish_feed | 0.567 | `hxxps://portaly[.]cc/emmanuel352` | tiny page: almost no text to judge | 17 | 0 | 0 | 0.0 |
| phish_feed | 0.806 | `hxxps://offshorekesuma[.]com/v2/wp-content/uploads/2024/08/redir_sal0508[.]html` | tiny page: almost no text to judge | 0 | 1 | 0 | 0.0 |
| phish_feed | 0.144 | `hxxps://l[.]ead[.]me/bgfiym` | on a shared hosting / link-shortener platform (the saved page may be the platform's own; domain with many phishing pages) | 459 | 1 | 0 | 0.03 |

## Random sample of wrongly flagged benign pages

| source | prob | url | cause | words | forms | password | ext link ratio |
|---|---|---|---|---|---|---|---|
| benign_tail | 0.953 | `https://vmailru.com/` | tiny page: almost no text to judge | 42 | 0 | 0 | 0.0 |
| benign_tail | 0.858 | `https://anineko.to/` | no obvious cause (ordinary page) | 119 | 0 | 0 | 0.0 |
| benign_tail | 0.854 | `https://volosatiki.xyz/` | mostly links / resources on other websites | 74 | 0 | 0 | 1.0 |
| benign_tail_login | 0.918 | `https://atea.no/account/login` | tiny page: almost no text to judge | 10 | 0 | 0 | 0.0 |
| benign_tail | 0.854 | `https://7298.casino/` | mostly links / resources on other websites | 74 | 0 | 0 | 1.0 |
| benign_tail_login | 0.901 | `https://machicomi.jp/login` | tiny page: almost no text to judge | 9 | 0 | 0 | 0.0 |
| benign_tail | 0.877 | `https://trep6das.com/` | tiny page: almost no text to judge | 38 | 0 | 0 | 0.0 |
| benign_top | 0.921 | `https://ad-delivery.net/` | tiny page: almost no text to judge | 26 | 0 | 0 | 0.0 |
