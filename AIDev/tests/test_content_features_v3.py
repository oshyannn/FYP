"""Unit tests for the six version-3 features in detection/content_features.py.  Run from AIDev/:
    python -m unittest tests.test_content_features_v3 -v"""
import unittest

from aidev.detection import content_features as cf

PAGE = "https://secure-login.example.xyz/signin"


def f(html, url=PAGE):
    return cf.extract(html, url)


class VersionTests(unittest.TestCase):
    def test_version_and_names(self):
        self.assertEqual(cf.CONTENT_FEATURE_VERSION, 3)
        self.assertEqual(len(cf.FEATURE_NAMES), len(set(cf.FEATURE_NAMES)))
        self.assertEqual(cf.FEATURE_NAMES[-6:], ["brand_asset_hotlink", "brand_in_logo_alt", "brand_in_meta", "n_ext_domains",
                                                 "login_form_no_own_links", "form_posts_to_ip_or_http"])
        self.assertEqual(set(f("<html></html>")), set(cf.FEATURE_NAMES))      # extract() returns exactly the names
        self.assertEqual(len(cf.vector("<html></html>", PAGE)), len(cf.FEATURE_NAMES))


class BrandAssetHotlink(unittest.TestCase):
    def test_image_from_real_brand_domain(self):
        self.assertEqual(f('<img src="https://www.paypal.com/images/logo.png">')["brand_asset_hotlink"], 1)

    def test_stylesheet_and_favicon_count(self):
        self.assertEqual(f('<link rel="stylesheet" href="https://static.maybank.com/a.css">')["brand_asset_hotlink"], 1)
        self.assertEqual(f('<link rel="shortcut icon" href="https://www.paypal.com/favicon.ico">')["brand_asset_hotlink"], 1)

    def test_scripts_do_not_count(self):
        self.assertEqual(f('<script src="https://www.google.com/recaptcha/api.js"></script>')["brand_asset_hotlink"], 0)

    def test_own_brand_and_unrelated_hosts_do_not_count(self):
        self.assertEqual(f('<img src="https://www.paypal.com/x.png">', "https://www.paypal.com/login")["brand_asset_hotlink"], 0)
        self.assertEqual(f('<img src="https://cdn.shop.org/x.png"><img src="/local.png">')["brand_asset_hotlink"], 0)


class BrandInLogoAlt(unittest.TestCase):
    def test_alt_text(self):
        self.assertEqual(f('<img src="/a.png" alt="PayPal">')["brand_in_logo_alt"], 1)

    def test_logo_file_name(self):
        self.assertEqual(f('<img src="/img/maybank-logo.png">')["brand_in_logo_alt"], 1)

    def test_brand_in_non_logo_file_name_does_not_count(self):
        self.assertEqual(f('<img src="/apple-touch-icon.png">')["brand_in_logo_alt"], 0)

    def test_own_brand_does_not_count(self):
        self.assertEqual(f('<img src="/a.png" alt="PayPal">', "https://www.paypal.com/")["brand_in_logo_alt"], 0)
        self.assertEqual(f('<img src="/a.png" alt="Our team">')["brand_in_logo_alt"], 0)


class BrandInMeta(unittest.TestCase):
    def test_site_name_application_name_description(self):
        self.assertEqual(f('<meta property="og:site_name" content="PayPal">')["brand_in_meta"], 1)
        self.assertEqual(f('<meta name="application-name" content="Maybank2u">')["brand_in_meta"], 1)
        self.assertEqual(f('<meta name="description" content="Log in to your Netflix account">')["brand_in_meta"], 1)

    def test_other_meta_and_own_brand_do_not_count(self):
        self.assertEqual(f('<meta name="keywords" content="paypal">')["brand_in_meta"], 0)
        self.assertEqual(f('<meta property="og:site_name" content="PayPal">', "https://paypal.com/")["brand_in_meta"], 0)

    def test_meta_refresh_still_detected(self):
        self.assertEqual(f('<meta http-equiv="refresh" content="0;url=http://x.com">')["meta_refresh"], 1)


class NExtDomains(unittest.TestCase):
    def test_counts_distinct_foreign_registered_domains(self):
        h = ('<a href="https://a.other.com/1">x</a><a href="https://b.other.com/2">y</a><img src="https://cdn.third.net/i.png">'
             '<script src="/own.js"></script><a href="/home">h</a><a href="mailto:a@b.c">m</a>')
        import math
        self.assertAlmostEqual(f(h)["n_ext_domains"], math.log1p(2))      # other.com and third.net

    def test_none(self):
        self.assertEqual(f('<a href="/a">a</a>')["n_ext_domains"], 0.0)


class LoginFormNoOwnLinks(unittest.TestCase):
    PW = '<form><input type="password"></form>'

    def test_password_page_without_own_links(self):
        self.assertEqual(f(self.PW + '<a href="https://other.com/x">x</a><a href="#">y</a>')["login_form_no_own_links"], 1)
        self.assertEqual(f(self.PW)["login_form_no_own_links"], 1)

    def test_password_page_with_own_link(self):
        self.assertEqual(f(self.PW + '<a href="/help">help</a>')["login_form_no_own_links"], 0)

    def test_no_password_field(self):
        self.assertEqual(f('<a href="https://other.com/x">x</a>')["login_form_no_own_links"], 0)


class FormPostsToIpOrHttp(unittest.TestCase):
    def test_ip_action(self):
        self.assertEqual(f('<form action="https://203.0.113.7/p.php"></form>')["form_posts_to_ip_or_http"], 1)

    def test_plain_http_absolute_action(self):
        self.assertEqual(f('<form action="http://collect.example.org/g"></form>')["form_posts_to_ip_or_http"], 1)

    def test_https_domain_and_relative_actions_do_not_count(self):
        self.assertEqual(f('<form action="https://collect.example.org/g"></form>')["form_posts_to_ip_or_http"], 0)
        self.assertEqual(f('<form action="post.php"></form>')["form_posts_to_ip_or_http"], 0)
        self.assertEqual(f('<form action="post.php"></form>', "http://plain-http-page.example.xyz/")["form_posts_to_ip_or_http"], 0)
        self.assertEqual(f('<form></form>')["form_posts_to_ip_or_http"], 0)

    def test_malformed_action_does_not_crash(self):
        self.assertEqual(f('<form action="http://[bad/x"></form>')["form_posts_to_ip_or_http"], 0)


class RobustnessTests(unittest.TestCase):
    def test_garbage_html_and_malformed_urls_do_not_raise(self):
        f('<img src="http://[::1/x.png"><a href="http://[bad">x</a><link rel="stylesheet" href="http://[x">')
        f("")
        f("<<<>>> <img alt=>")


if __name__ == "__main__":
    unittest.main()
