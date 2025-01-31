from pymongo import MongoClient
from app.config import MONGO_URI, DATABASE_NAME


def connect_db():
    """
    Establish a connection to MongoDB.
    If the database exists, drop all collections to clear data.

    Returns:
        db (Database): A new MongoDB database connection.
    """
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]
    return db

def init_db():
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]


    # Check if the database exists by looking for collections
    existing_collections = db.list_collection_names()

    if existing_collections:
        print(f"Database '{DATABASE_NAME}' exists. Dropping all collections...")
        for collection in existing_collections:
            db[collection].drop()  # Drop each collection
        print("All collections dropped. Database is now empty.")

    print(f"Connected to MongoDB database: {DATABASE_NAME}")

    return db