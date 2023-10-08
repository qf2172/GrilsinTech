from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.schema import PrimaryKeyConstraint
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:114324@localhost/hacdatabase'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To suppress a warning message
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user data store (replace this with a real database)
#users = {"qf2172": {"password": "123456", "id": 1}}

class User(db.Model,UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    courses = db.relationship('Course', backref='user', lazy=True,cascade='all, delete-orphan')

    # Method to set password hash
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Method to check password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(128), nullable=False)
    syllabus = db.Column(db.Text, nullable=True)
    description = db.Column(db.Text, nullable=True)
    professor_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    lecture_notes = db.relationship('LectureNote', backref='course', lazy=True,cascade='all, delete-orphan')

class LectureNote(db.Model):
    id = db.Column(db.Integer, nullable=False)
    chapter_name = db.Column(db.String(128), nullable=False)
    content = db.Column(db.Text, nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id', ondelete='CASCADE'), nullable=False)
    __table_args__ = (
        PrimaryKeyConstraint('id', 'course_id'),
    )
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def welcome():
    return render_template('welcome.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        # Check if user exists and password is correct
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if a user with this username or email already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)).first()

        if existing_user:
            flash('Username or email already exists. Choose another one.')
            return redirect(url_for('signup'))

        # Create a new user and hash the password
        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        # Log the user in after signup
        login_user(new_user)
        flash('Thanks for registering!')
        return redirect(url_for('dashboard'))

    return render_template('signup.html')


@app.route('/dashboard')
@login_required
def dashboard():
    # Assuming current_user from Flask-Login is imported
    courses = current_user.courses
    return render_template('dashboard.html', courses=courses)

@app.route('/create-course', methods=['GET', 'POST'])
def create_course():
    return render_template('create_course.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
