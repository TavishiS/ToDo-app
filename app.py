from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pytz

app = Flask(__name__)
app.secret_key = 'todo_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db'  # Second DB for users
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ToDo model
class ToDo(db.Model):
    __tablename__ = 'todo'
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now(pytz.utc))
    user_id = db.Column(db.Integer, nullable=False)

    def __repr__(self) -> str:
        return f"{self.sno} - {self.title} - {self.date_created}"

# Signup/User model
class Signup(UserMixin, db.Model):
    __bind_key__ = 'users'
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False, unique=True)  # username must be unique
    email = db.Column(db.String(200), nullable=False, unique=True)     # email must be unique
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self) -> str:
        return f"{self.id} - {self.username} - {self.email}"

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Signup.query.get(int(user_id))

# Routes

@app.route('/')
def about():
    if current_user.is_authenticated:
        return render_template('about_user.html')
    else:
        return render_template('about_guest.html')

@app.route('/about_guest')
def home_guest():
    return render_template('about_guest.html')

@app.route('/about_user')
def home_user():
    return render_template('about_user.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']

        # Check if email or username already exists
        existing_email = Signup.query.filter_by(email=email).first()
        existing_username = Signup.query.filter_by(username=username).first()

        if existing_email:
            error = "This email is already registered. Please <a href='/login'>login</a> or use a different email."
            return render_template('signup.html', error=error)

        if existing_username:
            error = "This username is already taken. Please choose a different one."
            return render_template('signup.html', error=error)

        hashed_password = generate_password_hash(password)
        user = Signup(email=email, username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=False)
        return redirect(url_for('create'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Signup.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=False)
            return redirect(url_for('create'))
        else:
            error = "Invalid credentials. Please <a href='/signup'>sign up</a> or try again."
            return render_template('login.html', error=error)
    return render_template('login.html')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        todo = ToDo(title=title, desc=desc, user_id=current_user.id)
        db.session.add(todo)
        db.session.commit()
    alltodos = ToDo.query.filter_by(user_id=current_user.id).all()
    return render_template('create.html', alltodos=alltodos)

@app.route('/update/<int:sno>', methods=['GET', 'POST'])
@login_required
def update(sno):
    todo = ToDo.query.filter_by(sno=sno, user_id=current_user.id).first()
    if request.method == 'POST':
        todo.title = request.form['title']
        todo.desc = request.form['desc']
        db.session.commit()
        return redirect(url_for('create'))
    return render_template('update.html', todo=todo)

@app.route('/delete/<int:sno>', methods=['GET', 'POST'])
@login_required
def delete(sno):
    todo = ToDo.query.filter_by(sno=sno, user_id=current_user.id).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('create'))

@app.route('/show')
@login_required
def show():
    alltodos = ToDo.query.filter_by(user_id=current_user.id).all()
    return render_template('show.html', alltodos=alltodos)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username, email=current_user.email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home_guest'))

if __name__ == '__main__':
    app.run(debug=True)