from pymongo import MongoClient

client = MongoClient('mongo', 27017)
db = client['event_manager']

# Συλλογές
users_collection = db['users']
events_collection = db['events']
