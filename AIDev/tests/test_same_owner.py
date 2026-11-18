"""Unit tests for aidev.evaluation.same_owner (own rules, no network).

Run from AIDev/ with the venv active:
    python -m unittest tests.test_same_owner -v
"""
import unittest

from aidev.evaluation.same_owner import copyright_owners, links_to, same_owner


class LinksTests(unittest.TestCase):
    def test_direct_link(self):
        self.assertTrue(links_to('<a href="https://shopee.com/x">x</a>', "shopee.com"))

    def test_subdomain_counts(self):
        self.assertTrue(links_to('<img src="https://cdn.shopee.com/a.png">', "shopee.com"))

    def test_other_domain_not_matched(self):
        # "notshopee.com" must not count as "shopee.com"
        self.assertFalse(links_to('<a href="https://notshopee.com/">x</a>', "shopee.com"))

    def test_no_links(self):
        self.assertFalse(links_to("<p>hello</p>", "shopee.com"))


class CopyrightTests(unittest.TestCase):
    def test_extracts_company_word(self):
        self.assertIn("shopee", copyright_owners("<footer>© 2024 Shopee Pte Ltd</footer>"))

    def test_stop_words_removed(self):
        owners = copyright_owners("<footer>Copyright 2024 All rights reserved</footer>")
        self.assertNotIn("rights", owners)
        self.assertNotIn("reserved", owners)

    def test_empty(self):
        self.assertEqual(copyright_owners("<p>no notice</p>"), set())


class SameOwnerTests(unittest.TestCase):
    def test_link_gives_same(self):
        res = same_owner("shopee.sg", '<a href="https://shopee.com/">x</a>', "shopee.com", "<p>x</p>")
        self.assertEqual(res["verdict"], "same")

    def test_shared_copyright_gives_same(self):
        a = "<footer>© 2024 Shopee Pte Ltd</footer>"
        b = "<footer>© 2023 Shopee Pte Ltd. All rights reserved.</footer>"
        self.assertEqual(same_owner("shopee.sg", a, "shopee.com", b)["verdict"], "same")

    def test_no_evidence_is_unknown_not_different(self):
        a = "<footer>© Example Travel Co</footer>"
        b = "<footer>© Other Bank Ltd</footer>"
        self.assertEqual(same_owner("example.org", a, "bank.example", b)["verdict"], "unknown")

    def test_registrant_different_gives_different(self):
        orgs = {"a.com": "Alpha Ltd", "b.com": "Beta Inc"}
        res = same_owner("a.com", "<p>x</p>", "b.com", "<p>y</p>", rdap_org=orgs.get)
        self.assertEqual(res["verdict"], "different")

    def test_registrant_same_gives_same(self):
        orgs = {"a.com": "Alpha Ltd", "b.com": "alpha-ltd"}
        res = same_owner("a.com", "<p>x</p>", "b.com", "<p>y</p>", rdap_org=orgs.get)
        self.assertEqual(res["verdict"], "same")

    def test_privacy_proxy_is_not_evidence(self):
        # Two different owners behind the same privacy proxy must NOT be called "same"
        orgs = {"a.com": "Domains By Proxy, LLC", "b.com": "Domains By Proxy, LLC"}
        res = same_owner("a.com", "<p>x</p>", "b.com", "<p>y</p>", rdap_org=orgs.get)
        self.assertEqual(res["verdict"], "unknown")

    def test_missing_registrant_is_unknown(self):
        res = same_owner("a.com", "<p>x</p>", "b.com", "<p>y</p>", rdap_org=lambda d: None)
        self.assertEqual(res["verdict"], "unknown")


if __name__ == "__main__":
    unittest.main()
