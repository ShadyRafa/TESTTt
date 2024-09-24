from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from pymongo.errors import DuplicateKeyError
from bson import ObjectId
import jwt
import datetime
from flask_login import LoginManager, login_required, login_user, current_user, logout_user

app = Flask(__name__)
app.config['MONGO_URI'] = "mongodb://mongo:27017/events_db"
app.config['SECRET_KEY'] = 'your_secret_key'  # Change to something secure

# Initialize MongoDB
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Το όνομα της σελίδας login


class User:
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(str(user['_id']), user['username'])
    return None


# Collection για τους χρήστες
users_collection = mongo.db.users

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']
    
    if users_collection.find_one({"username": username}) or users_collection.find_one({"email": email}):
        return jsonify({"error": "Username or email already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    user = {
        "first_name": data['first_name'],
        "last_name": data['last_name'],
        "email": email,
        "username": username,
        "password": hashed_password
    }

    users_collection.insert_one(user)
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = users_collection.find_one({"username": username})
    if user and bcrypt.check_password_hash(user['password'], password):
        token = jwt.encode({
            'user_id': str(user['_id']),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        login_user(User(str(user['_id']), username))  # Login ο χρήστης
        return jsonify({"token": token}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_event', methods=['POST'])
def create_event():
    token = request.headers.get('Authorization').split()[1]
    try:
        user_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        return jsonify({"error": "Invalid token"}), 401

    data = request.get_json()
    event = {
        "name": data['name'],
        "description": data['description'],
        "date": data['date'],
        "time": data['time'],
        "location": data['location'],
        "type": data['type'],
        "creator_id": ObjectId(user_data['user_id']),
        "created_at": datetime.datetime.utcnow()
    }
    
    mongo.db.events.insert_one(event)
    return jsonify({"message": "Event created successfully"}), 201


@app.route('/my_events', methods=['GET'])
@login_required
def my_events():
    events = mongo.db.events.find({'created_by': session['username']})
    return render_template('my_events.html', events=events)

@app.route('/all_events', methods=['GET'])
@login_required
def all_events():
    events = mongo.db.events.find({'event_date': {'$gte': datetime.now()}})
    return render_template('all_events.html', events=events)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        query = request.form.get('query')
        filter_type = request.form.get('filter_type')
        events = mongo.db.events.find({filter_type: {'$regex': query, '$options': 'i'}})
        return render_template('search_results.html', events=events)
    return render_template('search.html')

@app.route('/event/<event_id>', methods=['GET'])
@login_required
def view_event(event_id):
    event = mongo.db.events.find_one({'_id': ObjectId(event_id)})
    participations = mongo.db.participations.find({'event_id': event_id})
    return render_template('event_detail.html', event=event, participations=participations)

@app.route('/event/<event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = mongo.db.events.find_one({'_id': ObjectId(event_id), 'created_by': current_user.username})
    if request.method == 'POST':
        updated_event = {
            'name': request.form.get('name'),
            'description': request.form.get('description'),
            'event_date': request.form.get('event_date'),
            'event_time': request.form.get('event_time'),
            'location': request.form.get('location'),
            'event_type': request.form.get('event_type')
        }
        mongo.db.events.update_one({'_id': ObjectId(event_id)}, {'$set': updated_event})
        return redirect(url_for('my_events'))
    return render_template('edit_event.html', event=event)


@app.route('/event/<event_id>/delete', methods=['POST'])
@login_required
def delete_event(event_id):
    mongo.db.events.delete_one({'_id': ObjectId(event_id), 'created_by': session['username']})
    return redirect(url_for('my_events'))
@app.route('/event/<event_id>/participate', methods=['POST'])
@login_required
def participate_event(event_id):
    status = request.form.get('status')  # 'coming' or 'maybe'
    participation = {
        'event_id': event_id,
        'user': session['username'],
        'status': status
    }
    mongo.db.participations.insert_one(participation)
    return redirect(url_for('view_event', event_id=event_id))
