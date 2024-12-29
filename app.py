
from flask import Flask, render_template, request, jsonify, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///copydata.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "sqlite:///copydata.db"

# Initialize database and migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # 'user' or 'admin'
    is_infected = db.Column(db.Boolean, default=False)  # True for infected, False for uninfected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to LoginActivity
    login_activities = db.relationship('LoginActivity', back_populates='user')

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to User
    user = db.relationship('User', back_populates='login_activities')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

# User routes
@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='user').first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = 'user'

            # Capture the location on login (latitude and longitude)
            latitude = request.form['latitude']  # assuming latitude is sent as form data
            longitude = request.form['longitude']  # assuming longitude is sent as form data

            # Store the login activity with location
            login_activity = LoginActivity(user_id=user.id, latitude=latitude, longitude=longitude)
            db.session.add(login_activity)
            db.session.commit()

            return redirect('/user/dashboard')
        else:
            return "Invalid username or password", 401

    return render_template('login.html')

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return "Username already exists!", 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role='user')

        db.session.add(new_user)
        try:
            db.session.commit()  # Commit to the database
            print("User successfully added")  # Debug statement
        except Exception as e:
            db.session.rollback()  # In case of error, rollback the session
            print(f"Error occurred: {e}")  # Print the error for debugging
            return "An error occurred. Please try again.", 500

        return redirect('/user/login')

    return render_template('signup.html')

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' in session and session.get('role') == 'user':
        user_activities = LoginActivity.query.filter_by(user_id=session['user_id']).all()

        # Debugging activity locations
        for activity in user_activities:
            print(f"Location of activity: {activity.latitude}, {activity.longitude}")

        return render_template('user_dashboard.html', user_activities=user_activities)
    return redirect('/user/login')

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = User.query.filter_by(username=username, role='admin').first()

        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['role'] = 'admin'
            return redirect('/admin/dashboard')
        else:
            return "Invalid admin username or password", 401

    return render_template('admin_login.html')

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return "Admin username already exists!", 400

        hashed_password = generate_password_hash(password)
        new_admin = User(username=username, password=hashed_password, role='admin')

        db.session.add(new_admin)
        try:
            db.session.commit()  # Commit to the database
            print("Admin successfully added")  # Debug statement
        except Exception as e:
            db.session.rollback()  # In case of error, rollback the session
            print(f"Error occurred: {e}")  # Print the error for debugging
            return "An error occurred. Please try again.", 500

        return redirect('/admin/login')

    return render_template('admin_signup.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' in session and session.get('role') == 'admin':
        users = User.query.filter_by(role='user').all()
        activities = LoginActivity.query.order_by(LoginActivity.timestamp.desc()).all()

        # Get all the locations
        user_locations = []
        for activity in activities:
            user_locations.append({
                'username': activity.user.username,  # Accessing the associated user
                'latitude': activity.latitude,
                'longitude': activity.longitude,
                'is_infected': activity.user.is_infected
            })

        return render_template('admin.html', users=users, user_locations=user_locations)

    return redirect('/admin/login')

@app.route('/update_location/<user_id>', methods=['POST'])
def update_location(user_id):
    # Assuming latitude and longitude values are passed in the POST request
    latitude = request.form['latitude']
    longitude = request.form['longitude']

    # Find the user
    user = User.query.get(user_id)

    if user:
        # Find the latest activity for the user
        user_activity = LoginActivity.query.filter_by(user_id=user.id).order_by(LoginActivity.timestamp.desc()).first()

        if user_activity:
            # Update the location
            user_activity.latitude = latitude
            user_activity.longitude = longitude
            db.session.commit()
            return "Location updated successfully", 200
        else:
            return "No activity found for the user", 404

    return "User not found", 404

@app.route('/update_status', methods=['POST'])
def update_status():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return "Unauthorized", 403

    data = request.json
    user_id = data.get('user_id')
    is_infected = data.get('is_infected')

    user = User.query.get(user_id)
    if user:
        user.is_infected = is_infected
        db.session.commit()
        return "Status updated", 200

    return "User not found", 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure location is initialized for first-time run
    
    port = int(os.environ.get("PORT", 5000))  # Use the PORT environment variable or default to 5000
    app.run(host="0.0.0.0", port=port, debug=True)

