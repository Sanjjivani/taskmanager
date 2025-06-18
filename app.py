import secrets
from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, abort, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import re
import os
import csv
from io import StringIO
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-123')

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/taskmaster'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    tasks = db.relationship('Task', backref='creator', lazy=True)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    completed = db.Column(db.Boolean, default=False)
    category = db.Column(db.String(50), default='Other')
    priority = db.Column(db.String(20), default='Medium')
    due_date = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subtasks = db.relationship('Subtask', backref='task', lazy=True)

class Subtask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    if ' ' in password:
        errors.append("Password must not contain whitespace")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)")
    if re.search(r"(.)\1{2,}", password):
        errors.append("Password must not contain 3 or more repetitive characters")
    return len(errors) == 0, errors

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()
        confirm_password = request.form.get('confirm_password').strip()
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        errors = []
        if not all([username, email, password, confirm_password]):
            errors.append('All fields are required')
        if len(username) < 4:
            errors.append('Username must be at least 4 characters')
        if not re.match(email_regex, email):
            errors.append('Invalid email format')
        if password != confirm_password:
            errors.append('Passwords do not match')
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists')
        if User.query.filter_by(email=email).first():
            errors.append('Email already exists')
        is_valid_password, password_errors = validate_password(password)
        errors.extend(password_errors)
        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            try:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
                new_user = User(username=username, email=email, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                try:
                    msg = Message(
                        subject='Welcome to TaskMaster!',
                        recipients=[email],
                        body=f'Hi {username},\n\nWelcome to TaskMaster! Your account has been successfully created.\n\nBest,\nThe TaskMaster Team',
                        html=f"""
                        <html>
                            <body style="font-family: 'Inter', Arial, sans-serif; color: #2d3436; background-color: #f5f6fa; margin: 0; padding: 20px;">
                                <div style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); overflow: hidden;">
                                    <div style="background: linear-gradient(90deg, #6c5ce7, #00cec9); padding: 20px; text-align: center;">
                                        <h1 style="color: #ffffff; font-size: 24px; margin: 0;">Welcome to TaskMaster!</h1>
                                    </div>
                                    <div style="padding: 30px;">
                                        <h2 style="color: #6c5ce7; font-size: 20px; margin-bottom: 20px;">Hi {username},</h2>
                                        <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                            Your TaskMaster account has been successfully created! 🎉 
                                            Get ready to organize your tasks with ease and efficiency.
                                        </p>
                                        <div style="text-align: center; margin: 30px 0;">
                                            <a href="{url_for('login', _external=True)}" style="display: inline-block; padding: 12px 24px; background: #6c5ce7; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
                                                Start Managing Your Tasks
                                            </a>
                                        </div>
                                        <p style="font-size: 14px; color: #636e72; text-align: center; margin-top: 20px;">
                                            Best regards,<br>The TaskMaster Team
                                        </p>
                                    </div>
                                    <div style="background: #dfe6e9; padding: 10px; text-align: center;">
                                        <p style="font-size: 12px; color: #2d3436; margin: 0;">
                                            © {datetime.now().year} TaskMaster. All rights reserved.
                                        </p>
                                    </div>
                                </div>
                            </body>
                        </html>
                        """
                    )
                    mail.send(msg)
                    flash('Account created successfully! A welcome email has been sent.', 'success')
                except Exception as e:
                    flash('Account created, but failed to send welcome email.', 'warning')
                    logger.error(f"Email error: {e}")
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Registration failed. Please try again.', 'error')
                logger.error(f"Signup error: {e}")
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password', 'error')
        else:
            login_user(user, remember=bool(request.form.get('remember')))
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    view = request.args.get('view', 'all')
    category_filter = request.args.get('category')
    priority_filter = request.args.get('priority')
    tasks_query = Task.query.filter_by(user_id=current_user.id)
    today = date.today()
    if view == 'today':
        tasks_query = tasks_query.filter(Task.due_date == today)
    elif view == 'upcoming':
        tasks_query = tasks_query.filter(Task.due_date > today)
    elif view == 'completed':
        tasks_query = tasks_query.filter_by(completed=True)
    if category_filter and category_filter != 'all':
        tasks_query = tasks_query.filter_by(category=category_filter)
    if priority_filter and priority_filter != 'all':
        tasks_query = tasks_query.filter_by(priority=priority_filter)
    tasks = tasks_query.order_by(Task.due_date).all()
    categories = sorted(set(task.category for task in Task.query.filter_by(user_id=current_user.id).all()))
    return render_template(
        'index.html',
        tasks=tasks,
        categories=['Work', 'Personal', 'Urgent', 'Shopping', 'Other'],
        priorities=['Low', 'Medium', 'High'],
        view=view,
        today=today,
        now=datetime.now().strftime('%Y-%m-%d %H:%M'),
        category_filter=category_filter or 'all',
        priority_filter=priority_filter or 'all'
    )

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    due_date = request.form.get('due_date')
    due_date_obj = datetime.strptime(due_date, '%Y-%m-%d').date() if due_date else None
    new_task = Task(
        text=request.form.get('task'),
        description=request.form.get('description', ''),
        category=request.form.get('category', 'Other'),
        priority=request.form.get('priority', 'Medium'),
        due_date=due_date_obj,
        user_id=current_user.id
    )
    db.session.add(new_task)
    db.session.commit()
    try:
        msg = Message(
            subject='New Task Created in TaskMaster',
            recipients=[current_user.email],
            body=f"""Hi {current_user.username},
A new task has been created successfully!
Task Details:
- Title: {new_task.text}
- Description: {new_task.description or 'No description provided'}
- Category: {new_task.category}
- Priority: {new_task.priority}
- Due Date: {new_task.due_date.strftime('%b %d, %Y') if new_task.due_date else 'No due date'}
The TaskMaster Team""",
            html=f"""
            <html>
                <body style="font-family: 'Inter', Arial, sans-serif; color: #2d3436; background-color: #f5f6fa; margin: 0; padding: 20px;">
                    <div style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); overflow: hidden;">
                        <div style="background: linear-gradient(90deg, #6c5ce7, #00cec9); padding: 20px; text-align: center;">
                            <h1 style="color: #ffffff; font-size: 24px; margin: 0;">New Task Created</h1>
                        </div>
                        <div style="padding: 30px;">
                            <h2 style="color: #6c5ce7; font-size: 20px; margin-bottom: 20px;">Hi {current_user.username},</h2>
                            <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                A new task has been successfully added to your TaskMaster account! 🚀
                            </p>
                            <h3 style="font-size: 18px; margin-bottom: 10px;">Task Details:</h3>
                            <ul style="font-size: 16px; line-height: 1.6; color: #2d3436; list-style: none; padding: 0;">
                                <li style="margin-bottom: 8px;"><strong>Title:</strong> {new_task.text}</li>
                                <li style="margin-bottom: 8px;"><strong>Description:</strong> {new_task.description or 'No description provided'}</li>
                                <li style="margin-bottom: 8px;"><strong>Category:</strong> {new_task.category}</li>
                                <li style="margin-bottom: 8px;"><strong>Priority:</strong> {new_task.priority}</li>
                                <li style="margin-bottom: 8px;"><strong>Due Date:</strong> {new_task.due_date.strftime('%b %d, %Y') if new_task.due_date else 'No due date'}</li>
                            </ul>
                            <div style="text-align: center; margin: 30px 0;">
                                <a href="{url_for('home', _external=True)}" style="display: inline-block; padding: 12px 24px; background: #6c5ce7; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
                                    View Your Tasks
                                </a>
                            </div>
                            <p style="font-size: 14px; color: #636e72; text-align: center; margin-top: 20px;">
                                Keep up the great work!<br>The TaskMaster Team
                            </p>
                        </div>
                        <div style="background: #dfe6e9; padding: 10px; text-align: center;">
                            <p style="font-size: 12px; color: #2d3436; margin: 0;">
                                © {datetime.now().year} TaskMaster. All rights reserved.
                            </p>
                        </div>
                    </div>
                </body>
            </html>
            """
        )
        mail.send(msg)
        flash('Task created successfully! A confirmation email has been sent.', 'success')
    except Exception as e:
        flash('Task created, but failed to send confirmation email.', 'warning')
        logger.error(f"Email error: {e}")
    view = 'all'
    if due_date_obj:
        today = date.today()
        if due_date_obj == today:
            view = 'today'
        elif due_date_obj > today:
            view = 'upcoming'
    return redirect(url_for('home', view=view))

@app.route('/update_task/<int:task_id>', methods=['POST'])
@login_required
def update_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    task.text = request.form.get('text', task.text)
    task.description = request.form.get('description', task.description)
    task.category = request.form.get('category', task.category)
    task.priority = request.form.get('priority', task.priority)
    task.completed = request.form.get('completed') == 'on'
    new_due_date = request.form.get('due_date')
    if new_due_date:
        task.due_date = datetime.strptime(new_due_date, '%Y-%m-%d').date()
    db.session.commit()
    view = request.args.get('view', 'all')
    if task.due_date:
        today = date.today()
        if task.due_date == today and view != 'completed':
            view = 'today'
        elif task.due_date > today and view != 'completed':
            view = 'upcoming'
    if task.completed:
        view = 'completed'
    return redirect(url_for('home', view=view, category=request.args.get('category'), priority=request.args.get('priority')))

@app.route("/delete/<int:task_id>", methods=["POST"])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/add_subtask/<int:task_id>', methods=['POST'])
@login_required
def add_subtask(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    subtask_text = request.form.get('subtask')
    if subtask_text:
        new_subtask = Subtask(text=subtask_text, task_id=task_id)
        db.session.add(new_subtask)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/toggle_subtask/<int:subtask_id>')
@login_required
def toggle_subtask(subtask_id):
    subtask = Subtask.query.get_or_404(subtask_id)
    task = Task.query.get_or_404(subtask.task_id)
    if task.user_id != current_user.id:
        abort(403)
    subtask.completed = not subtask.completed
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/download_tasks')
@login_required
def download_tasks():
    tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at).all()
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Title', 'Description', 'Category', 'Priority', 'Due Date', 'Completed', 'Created At', 'Subtasks'])
    for task in tasks:
        subtasks = '; '.join([f"{subtask.text} ({'Completed' if subtask.completed else 'Not Completed'})" for subtask in task.subtasks])
        writer.writerow([
            task.id,
            task.text,
            task.description or '',
            task.category,
            task.priority,
            task.due_date.strftime('%Y-%m-%d') if task.due_date else 'No due date',
            'Yes' if task.completed else 'No',
            task.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            subtasks or 'None'
        ])
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=taskmaster_tasks_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-type'] = 'text/csv'
    flash('Tasks downloaded successfully!', 'success')
    return response

@app.route('/task_progress')
@login_required
def task_progress():
    total_tasks = Task.query.filter_by(user_id=current_user.id).count()
    completed_tasks = Task.query.filter_by(user_id=current_user.id, completed=True).count()
    incomplete_tasks = total_tasks - completed_tasks
    return jsonify({
        'completed': completed_tasks,
        'incomplete': incomplete_tasks,
        'total': total_tasks
    })

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email').strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            logger.debug(f"Generated token for user {user.id}: {token}")
            logger.debug(f"Stored token: {user.reset_token}, Expiry: {user.reset_token_expiry}")
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message(
                "Password Reset Request",
                recipients=[email],
                html=f"""
                <html>
                    <body style="font-family: 'Inter', Arial, sans-serif; color: #2d3436; background-color: #f5f6fa; margin: 0; padding: 20px;">
                        <div style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); overflow: hidden;">
                            <div style="background: linear-gradient(90deg, #6c5ce7, #00cec9); padding: 20px; text-align: center;">
                                <h1 style="color: #ffffff; font-size: 24px; margin: 0;">Password Reset Request</h1>
                            </div>
                            <div style="padding: 30px;">
                                <h2 style="color: #6c5ce7; font-size: 20px; margin-bottom: 20px;">Hi {user.username},</h2>
                                <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                    We received a request to reset your TaskMaster password. Click the button below to reset it:
                                </p>
                                <div style="text-align: center; margin: 30px 0;">
                                    <a href="{reset_url}" style="display: inline-block; padding: 12px 24px; background: #6c5ce7; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
                                        Reset Password
                                    </a>
                                </div>
                                <p style="font-size: 14px; color: #636e72;">
                                    If you didn't request this, please ignore this email. This link will expire in 1 hour.
                                </p>
                                <p style="font-size: 12px; color: #636e72; margin-top: 20px;">
                                    Or copy and paste this link in your browser:<br>
                                    {reset_url}
                                </p>
                            </div>
                            <div style="background: #dfe6e9; padding: 10px; text-align: center;">
                                <p style="font-size: 12px; color: #2d3436; margin: 0;">
                                    © {datetime.now().year} TaskMaster. All rights reserved.
                                </p>
                            </div>
                        </div>
                    </body>
                </html>
                """
            )
            mail.send(msg)
            flash('A password reset link has been sent to your email.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.query.filter_by(reset_token=token).first()
    logger.debug(f"Reset password attempt with token: {token}")
    if user:
        logger.debug(f"Found user {user.id}, token: {user.reset_token}, expiry: {user.reset_token_expiry}")
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired token.', 'error')
        logger.warning(f"Invalid or expired token: {token}")
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password').strip()
        confirm_password = request.form.get('confirm_password').strip()
        errors = []
        if password != confirm_password:
            errors.append('Passwords do not match.')
        is_valid_password, password_errors = validate_password(password)
        errors.extend(password_errors)
        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            user.password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            flash('Your password has been updated! Please login with your new password.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        current_password = request.form.get('current_password').strip()
        new_password = request.form.get('new_password').strip()
        confirm_password = request.form.get('confirm_password').strip()
        
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        errors = []

        # Verify current password for any changes
        if not check_password_hash(current_user.password, current_password):
            errors.append('Current password is incorrect.')

        # Validate username
        if username != current_user.username:
            if len(username) < 4:
                errors.append('Username must be at least 4 characters.')
            if User.query.filter_by(username=username).first():
                errors.append('Username already exists.')

        # Validate email
        if email != current_user.email:
            if not re.match(email_regex, email):
                errors.append('Invalid email format.')
            if User.query.filter_by(email=email).first():
                errors.append('Email already exists.')

        # Validate new password
        if new_password:
            if new_password != confirm_password:
                errors.append('New passwords do not match.')
            is_valid_password, password_errors = validate_password(new_password)
            errors.extend(password_errors)

        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            try:
                # Update user details
                if username != current_user.username:
                    current_user.username = username
                if email != current_user.email:
                    old_email = current_user.email
                    current_user.email = email
                    # Send confirmation email to old and new email
                    try:
                        msg = Message(
                            subject='TaskMaster Email Updated',
                            recipients=[old_email, email],
                            body=f"""Hi {username},
Your TaskMaster email has been updated to {email}.
If you did not make this change, please contact support.
The TaskMaster Team""",
                            html=f"""
                            <html>
                                <body style="font-family: 'Inter', Arial, sans-serif; color: #2d3436; background-color: #f5f6fa; margin: 0; padding: 20px;">
                                    <div style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); overflow: hidden;">
                                        <div style="background: linear-gradient(90deg, #6c5ce7, #00cec9); padding: 20px; text-align: center;">
                                            <h1 style="color: #ffffff; font-size: 24px; margin: 0;">Email Updated</h1>
                                        </div>
                                        <div style="padding: 30px;">
                                            <h2 style="color: #6c5ce7; font-size: 20px; margin-bottom: 20px;">Hi {username},</h2>
                                            <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                                Your TaskMaster email has been successfully updated to <strong>{email}</strong>.
                                            </p>
                                            <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                                If you did not make this change, please contact our support team immediately.
                                            </p>
                                            <div style="text-align: center; margin: 30px 0;">
                                                <a href="{url_for('home', _external=True)}" style="display: inline-block; padding: 12px 24px; background: #6c5ce7; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
                                                    View Your Tasks
                                                </a>
                                            </div>
                                            <p style="font-size: 14px; color: #636e72; text-align: center; margin-top: 20px;">
                                                Best regards,<br>The TaskMaster Team
                                            </p>
                                        </div>
                                        <div style="background: #dfe6e9; padding: 10px; text-align: center;">
                                            <p style="font-size: 12px; color: #2d3436; margin: 0;">
                                                © {datetime.now().year} TaskMaster. All rights reserved.
                                            </p>
                                        </div>
                                    </div>
                                </body>
                            </html>
                            """
                        )
                        mail.send(msg)
                    except Exception as e:
                        logger.error(f"Email update notification error: {e}")
                if new_password:
                    current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)
                    # Send password change confirmation
                    try:
                        msg = Message(
                            subject='TaskMaster Password Updated',
                            recipients=[current_user.email],
                            body=f"""Hi {username},
Your TaskMaster password has been updated.
If you did not make this change, please contact support.
The TaskMaster Team""",
                            html=f"""
                            <html>
                                <body style="font-family: 'Inter', Arial, sans-serif; color: #2d3436; background-color: #f5f6fa; margin: 0; padding: 20px;">
                                    <div style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); overflow: hidden;">
                                        <div style="background: linear-gradient(90deg, #6c5ce7, #00cec9); padding: 20px; text-align: center;">
                                            <h1 style="color: #ffffff; font-size: 24px; margin: 0;">Password Updated</h1>
                                        </div>
                                        <div style="padding: 30px;">
                                            <h2 style="color: #6c5ce7; font-size: 20px; margin-bottom: 20px;">Hi {username},</h2>
                                            <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                                Your TaskMaster password has been successfully updated.
                                            </p>
                                            <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                                If you did not make this change, please contact our support team immediately.
                                            </p>
                                            <div style="text-align: center; margin: 30px 0;">
                                                <a href="{url_for('home', _external=True)}" style="display: inline-block; padding: 12px 24px; background: #6c5ce7; color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
                                                    View Your Tasks
                                                </a>
                                            </div>
                                            <p style="font-size: 14px; color: #636e72; text-align: center; margin-top: 20px;">
                                                Best regards,<br>The TaskMaster Team
                                            </p>
                                        </div>
                                        <div style="background: #dfe6e9; padding: 10px; text-align: center;">
                                            <p style="font-size: 12px; color: #2d3436; margin: 0;">
                                                © {datetime.now().year} TaskMaster. All rights reserved.
                                            </p>
                                        </div>
                                    </div>
                                </body>
                            </html>
                            """
                        )
                        mail.send(msg)
                    except Exception as e:
                        logger.error(f"Password update notification error: {e}")
                
                db.session.commit()
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('profile'))
            except Exception as e:
                db.session.rollback()
                flash('Profile update failed. Please try again.', 'error')
                logger.error(f"Profile update error: {e}")

    return render_template('profile.html', user=current_user)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        user_email = current_user.email
        user_username = current_user.username
        # Delete all tasks and subtasks associated with the user
        Task.query.filter_by(user_id=current_user.id).delete()
        Subtask.query.filter(Task.user_id == current_user.id).delete()
        # Delete the user
        db.session.delete(current_user)
        db.session.commit()
        # Send account deletion confirmation email
        try:
            msg = Message(
                subject='TaskMaster Account Deleted',
                recipients=[user_email],
                body=f"""Hi {user_username},
Your TaskMaster account has been successfully deleted.
If you did not request this action, please contact support immediately.
Thank you for using TaskMaster!
The TaskMaster Team""",
                html=f"""
                <html>
                    <body style="font-family: 'Inter', Arial, sans-serif; color: #2d3436; background-color: #f5f6fa; margin: 0; padding: 20px;">
                        <div style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); overflow: hidden;">
                            <div style="background: linear-gradient(90deg, #6c5ce7, #00cec9); padding: 20px; text-align: center;">
                                <h1 style="color: #ffffff; font-size: 24px; margin: 0;">Account Deleted</h1>
                            </div>
                            <div style="padding: 30px;">
                                <h2 style="color: #6c5ce7; font-size: 20px; margin-bottom: 20px;">Hi {user_username},</h2>
                                <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                    Your TaskMaster account has been successfully deleted.
                                </p>
                                <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                    If you did not request this action, please contact our support team immediately.
                                </p>
                                <p style="font-size: 16px; line-height: 1.6; color: #2d3436;">
                                    Thank you for using TaskMaster!
                                </p>
                                <p style="font-size: 14px; color: #636e72; text-align: center; margin-top: 20px;">
                                    Best regards,<br>The TaskMaster Team
                                </p>
                            </div>
                            <div style="background: #dfe6e9; padding: 10px; text-align: center;">
                                <p style="font-size: 12px; color: #2d3436; margin: 0;">
                                    © {datetime.now().year} TaskMaster. All rights reserved.
                                </p>
                            </div>
                        </div>
                    </body>
                </html>
                """
            )
            mail.send(msg)
        except Exception as e:
            logger.error(f"Account deletion notification error: {e}")
        logout_user()
        flash('Your account has been deleted successfully.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete account. Please try again.', 'error')
        logger.error(f"Account deletion error: {e}")
        return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)