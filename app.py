# app.py
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId  # مهم لتعامل Flask-Login مع MongoDB
from forms import LoginForm, RegistrationForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['MONGO_URI'] = 'mongodb+srv://tncxzml:CPsMBvK4w47HOsU0@cardify.05dzz.mongodb.net/auth_database'

# Initialize extensions
bootstrap = Bootstrap(app)
mongo = PyMongo(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user_data:
            return None
        return User(user_data)
    except:
        return None

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = mongo.db.users.find_one({'email': form.email.data})
        if existing_user:
            flash('Email already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        mongo.db.users.insert_one({
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password
        })

        # تسجيل الدخول تلقائيًا بعد التسجيل
        user_data = mongo.db.users.find_one({'email': form.email.data})
        user = User(user_data)
        login_user(user)

        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_data = mongo.db.users.find_one({'email': form.email.data})
        if user_data and check_password_hash(user_data['password'], form.password.data):
            user = User(user_data)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
