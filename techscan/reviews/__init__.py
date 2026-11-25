"""Competitor customers that leave no trace on the storefront.

Some Shopify analytics apps (Peel, BeProfit, TrueProfit, Lifetimely...) connect only through the
Shopify Admin API, so no crawler can see them. Their customers can still be found:

1. collect.py - Shopify App Store reviews name the reviewing store (plus country, months of use,
                rating). 1-star reviews first: unhappy customers are the warmest leads.
2. resolve.py - store name -> verified Shopify domain (myshopify redirect, domain guesses,
                Shopify + name-match verification). Never guessed: unverified stays unresolved.
3. learn.py   - reviewer stores are a labelled set: an `apiClientId` that shows up in the Web
                Pixels manifest of many BeProfit reviewers and rarely elsewhere *is* BeProfit's
                pixel id. The learned ids then detect the app on any Shopify store.
"""
from pathlib import Path

from .. import ROOT

DATA_DIR = ROOT / "data" / "reviews"
REVIEWS_FILE = DATA_DIR / "reviews.json"
STORES_FILE = DATA_DIR / "stores.json"
APP_IDS_FILE = ROOT / "config" / "shopify_app_ids.json"


def ensure_dir() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR
