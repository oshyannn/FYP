# Error analysis experiments\m2_v3_preds.csv

- threshold (raw probability, 1% false-positive rate on this test set): 0.8002
- test pages 3085: phishing 1330, benign 1755
- missed phishing pages (false negatives): 614 (46.2%)
- wrongly flagged benign pages (false positives): 17 (1.0%)

## Why phishing pages were missed (all of them)

| cause | pages | share |
|---|---|---|
| tiny page: almost no text to judge | 190 | 30.9% |
| no form at all (landing / lure page) | 154 | 25.1% |
| has a form, nothing sensitive | 147 | 23.9% |
| redirector page (meta refresh or JavaScript redirect) | 68 | 11.1% |
| has a credential form but no other strong signal | 51 | 8.3% |
| on a shared hosting / link-shortener platform (the saved page may be the platform's own) | 4 | 0.7% |

False negatives by source: phreshphish_phish 462, phish_feed 152

## Why benign pages were flagged (all of them)

| cause | pages | share |
|---|---|---|
| tiny page: almost no text to judge | 13 | 76.5% |
| no obvious cause (ordinary page) | 2 | 11.8% |
| real login / payment form | 1 | 5.9% |
| mostly links / resources on other websites | 1 | 5.9% |

False positives by source: benign_tail 8, phreshphish_benign 8, benign_top_login 1

## Random sample of missed phishing pages (URLs defanged: do NOT open)

| source | prob | url | cause | words | forms | password | ext link ratio |
|---|---|---|---|---|---|---|---|
| phreshphish_phish | 0.666 | `hxxps://cobezayt[.]com` | has a credential form but no other strong signal | 1090 | 2 | 1 | 0.0 |
| phreshphish_phish | 0.673 | `hxxps://t5-zhifejijiweb[.]com/` | no form at all (landing / lure page) | 144 | 0 | 0 | 0.08 |
| phreshphish_phish | 0.775 | `hxxps://wedwhetsapp[.]com/` | no form at all (landing / lure page) | 318 | 0 | 0 | 1.0 |
| phreshphish_phish | 0.775 | `hxxp://he-whatsaqq[.]com/` | no form at all (landing / lure page) | 318 | 0 | 0 | 1.0 |
| phish_feed | 0.263 | `hxxps://online[.]multa[.]net/` | redirector page (meta refresh or JavaScript redirect) | 66 | 4 | 1 | 0.0 |
| phreshphish_phish | 0.294 | `hxxps://nomuaissieo[.]com` | tiny page: almost no text to judge | 0 | 0 | 0 | 0.0 |
| phreshphish_phish | 0.174 | `hxxp://royalmail[.]com-trackinglink[.]icu` | has a form, nothing sensitive | 703 | 3 | 0 | 0.37 |
| phish_feed | 0.555 | `hxxps://ee[.]kobotoolbox[.]org/x/hxh6atau` | redirector page (meta refresh or JavaScript redirect) | 89 | 0 | 0 | 0.0 |
| phreshphish_phish | 0.362 | `hxxps://app[.]seesaw[.]me/pages/shared_item?item_id=item[.]97c7f6eb-7b81-4c5f-8306-eee6a4258cbf&share_token=YT2_q53VSo-DX3C183cXoA&mode=share` | tiny page: almost no text to judge | 9 | 0 | 0 | 0.0 |
| phish_feed | 0.148 | `hxxps://qrco[.]de/bfsudc` | has a form, nothing sensitive | 862 | 1 | 0 | 0.23 |
| phreshphish_phish | 0.238 | `hxxps://cas[.]univ-montp3[.]fr/cas/login` | has a credential form but no other strong signal | 71 | 1 | 1 | 0.25 |
| phreshphish_phish | 0.602 | `hxxps://sparka-vorgang-sicherheit[.]net/` | has a form, nothing sensitive | 712 | 1 | 0 | 1.0 |
| phish_feed | 0.387 | `hxxps://l[.]ead[.]me/bgzpvi` | no form at all (landing / lure page) | 604 | 0 | 0 | 0.0 |
| phreshphish_phish | 0.648 | `hxxp://oszar[.]com/` | tiny page: almost no text to judge | 32 | 1 | 0 | 0.67 |
| phish_feed | 0.534 | `hxxp://lodgevinasdelsol[.]com/` | has a form, nothing sensitive | 480 | 1 | 0 | 0.31 |
| phreshphish_phish | 0.415 | `hxxp://jellyfishglow[.]top/` | has a form, nothing sensitive | 318 | 2 | 0 | 0.0 |
| phreshphish_phish | 0.418 | `hxxps://drskool[.]com/product/wall-breast-and-body-contouring-video-library-volume-3/` | has a form, nothing sensitive | 428 | 5 | 0 | 0.0 |
| phish_feed | 0.767 | `hxxp://www[.]roblox[.]com[.]ml/users/265132121929/profile/` | tiny page: almost no text to judge | 18 | 0 | 0 | 1.0 |
| phreshphish_phish | 0.648 | `hxxps://eebndss[.]mmm[.]page/` | tiny page: almost no text to judge | 14 | 0 | 0 | 0.5 |
| phreshphish_phish | 0.48 | `hxxps://app[.]jotform[.]com/250206932962154` | on a shared hosting / link-shortener platform (the saved page may be the platform's own) | 8 | 0 | 0 | 0.0 |
| phreshphish_phish | 0.599 | `hxxp://myinsurlife[.]com/` | has a form, nothing sensitive | 438 | 1 | 0 | 0.0 |
| phreshphish_phish | 0.666 | `hxxps://myworkspaceb2315[.]myclickfunnels[.]com/dgt` | has a form, nothing sensitive | 2093 | 3 | 0 | 0.99 |
| phreshphish_phish | 0.736 | `hxxp://myfedex-delivery[.]com` | tiny page: almost no text to judge | 0 | 0 | 0 | 0.0 |
| phreshphish_phish | 0.553 | `hxxp://xingsijin[.]com/` | has a form, nothing sensitive | 257 | 2 | 0 | 0.19 |
| phreshphish_phish | 0.638 | `hxxps://trackinglbz[.]life/ch/payment[.]html` | tiny page: almost no text to judge | 0 | 0 | 0 | 0.0 |
| phreshphish_phish | 0.716 | `hxxps://go[.]sniply[.]page/?url=https%3A%2F%2Fchat[.]whatsapp[.]com%2F` | redirector page (meta refresh or JavaScript redirect) | 417 | 0 | 0 | 1.0 |
| phreshphish_phish | 0.666 | `hxxps://mysolveshrnis[.]com/` | redirector page (meta refresh or JavaScript redirect) | 66 | 2 | 1 | 0.0 |
| phreshphish_phish | 0.69 | `hxxps://ch[.]cemabra[.]app/ch/ui/app/4d9c1b/connect[.]php?flow=ch-CH&app=ODEuMjIxLjY1LjIz` | tiny page: almost no text to judge | 56 | 1 | 0 | 1.0 |
| phreshphish_phish | 0.294 | `hxxps://nomruajapanb[.]com` | tiny page: almost no text to judge | 0 | 0 | 0 | 0.0 |
| phreshphish_phish | 0.419 | `hxxps://wgihh[.]cn/rakusec` | no form at all (landing / lure page) | 256 | 0 | 0 | 0.21 |

## Random sample of wrongly flagged benign pages

| source | prob | url | cause | words | forms | password | ext link ratio |
|---|---|---|---|---|---|---|---|
| benign_tail | 0.822 | `https://gisnauka.ru/` | tiny page: almost no text to judge | 18 | 0 | 0 | 0.0 |
| benign_tail | 0.817 | `https://datev-status.de/` | tiny page: almost no text to judge | 37 | 0 | 0 | 0.8 |
| benign_tail | 0.83 | `https://e-szigno.hu/` | tiny page: almost no text to judge | 46 | 0 | 0 | 0.0 |
| phreshphish_benign | 0.869 | `https://bconline.broward.edu/d2l/home/655932` | tiny page: almost no text to judge | 23 | 1 | 0 | 0.0 |
| phreshphish_benign | 0.873 | `https://myfire.seu.edu/d2l/home/8104` | tiny page: almost no text to judge | 27 | 1 | 0 | 1.0 |
| phreshphish_benign | 0.893 | `https://sbli.ace.swissre.com/` | mostly links / resources on other websites | 201 | 0 | 0 | 1.0 |
| benign_tail | 0.886 | `https://norest.shop/` | no obvious cause (ordinary page) | 105 | 0 | 0 | 0.0 |
| phreshphish_benign | 0.835 | `https://rsdairy.rakurakuseisan.jp/zjzbu8tcqqa/sapkosaiseishoninkensaku/initializeview` | tiny page: almost no text to judge | 2 | 0 | 0 | 0.0 |
| benign_top_login | 0.804 | `https://tynt.com/account/login` | tiny page: almost no text to judge | 45 | 0 | 0 | 0.75 |
| phreshphish_benign | 0.857 | `https://paynow.stgusa.com/stgepayments/` | tiny page: almost no text to judge | 36 | 0 | 0 | 0.0 |
| phreshphish_benign | 0.842 | `https://td.doubleclick.net/td/rul/16449917397` | tiny page: almost no text to judge | 0 | 0 | 0 | 0.0 |
| benign_tail | 0.821 | `https://narayanverma.com/` | tiny page: almost no text to judge | 12 | 0 | 0 | 0.0 |
| benign_tail | 0.804 | `https://janning.info/` | tiny page: almost no text to judge | 3 | 0 | 0 | 0.0 |
| phreshphish_benign | 0.811 | `https://sitebeat.crazydomains.com/editor/61444b23-2c18-4b2e-87ae-0c20ea98938c/3e3cc099-2beb-4620-a339-72dcf439671d` | real login / payment form | 22 | 1 | 1 | 0.0 |
| phreshphish_benign | 0.817 | `https://www.outerknown.com/wpm@77ccadb9w87488b4epca16f10em2f02054c/custom/web-pixel-30539960@1/sandbox/modern/collections/mens-sale-bottoms` | tiny page: almost no text to judge | 0 | 0 | 0 | 0.0 |
| benign_tail | 0.888 | `https://embed-player.space/` | no obvious cause (ordinary page) | 108 | 0 | 0 | 0.0 |
| benign_tail | 0.859 | `https://quickdns.net/` | tiny page: almost no text to judge | 42 | 1 | 0 | 1.0 |
