from pymongo import MongoClient
import os

class DatabaseConnection:
    def __init__(self):
        mongo_uri = os.getenv('MONGO_URI', 'mongodb://root:secret@mongo:27017/devices')
        self.client = MongoClient(mongo_uri)
        self.db = self.client['devices']
    
    def get_database(self):
        return self.db
