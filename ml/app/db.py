from __future__ import annotations

import os

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database


_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
        _client = MongoClient(uri, serverSelectionTimeoutMS=2000)
    return _client


def get_db() -> Database:
    name = os.environ.get("MONGO_DB", "latentguard")
    return get_client()[name]


def requests_collection() -> Collection:
    return get_db()["requests"]


def rules_collection() -> Collection:
    return get_db()["rules_queue"]
