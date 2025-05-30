from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
db = client["basket"]
users_collection = db["latihan"]
