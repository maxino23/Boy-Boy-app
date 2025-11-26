import os
import logging
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, time
from werkzeug.utils import secure_filename
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_secret_key_for_boy_boy_app')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///errands.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max file size

# Database connection management
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True
}

# Configure upload folders
UPLOAD_FOLDER = 'static/payment_proofs'
PROFILE_PICS_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROFILE_PICS_FOLDER'] = PROFILE_PICS_FOLDER

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)  # 'user' or 'runner'
    phone = db.Column(db.String(20))
    is_admin = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(255), default='default_avatar.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # FIXED: Relationships with unique backref names
    errands_posted = db.relationship('Errand', 
                                    foreign_keys='Errand.poster_id', 
                                    backref='poster', 
                                    lazy=True)
    errands_accepted = db.relationship('Errand', 
                                      foreign_keys='Errand.runner_id', 
                                      backref='runner', 
                                      lazy=True)

class Errand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    budget = db.Column(db.Float, nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='open')  # open, in_progress, completed, cancelled
    category = db.Column(db.String(50))
    payment_status = db.Column(db.String(20), default='unpaid')  # unpaid, pending, paid
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign Keys
    poster_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    runner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # New fields for acceptance system
    accepted_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # Foreign Keys
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    errand_id = db.Column(db.Integer, db.ForeignKey('errand.id'), nullable=False)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    errand = db.relationship('Errand', backref='messages')

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed, cancelled
    payment_method = db.Column(db.String(50))  # mobile_money, cash, bank_transfer
    payment_proof = db.Column(db.String(255))  # URL to payment screenshot
    payer_phone = db.Column(db.String(20))
    payee_phone = db.Column(db.String(20))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Foreign Keys
    errand_id = db.Column(db.Integer, db.ForeignKey('errand.id'), nullable=False)
    payer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    payee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    errand = db.relationship('Errand', backref='payments')
    payer = db.relationship('User', foreign_keys=[payer_id], backref='payments_made')
    payee = db.relationship('User', foreign_keys=[payee_id], backref='payments_received')

def allowed_file(filename):
    """Improved file validation"""
    if not filename or '.' not in filename:
        return False
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ==================== CONTEXT PROCESSOR ====================
@app.context_processor
def inject_user():
    """Make current user available to all templates"""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return {'current_user': user}
    return {'current_user': None}

# ==================== ADMIN AUTHORIZATION ====================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    """Check if current user is admin"""
    if 'user_id' not in session:
        return False
    user = User.query.get(session['user_id'])
    return user and (user.is_admin or user.email == 'admin@boyboy.com')

# Initialize database with sample data
def init_db():
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database tables created successfully!")
            
            # Add sample data if no users exist
            if User.query.count() == 0:
                add_sample_data()
                print("✅ Sample data added!")
        except Exception as e:
            print(f"❌ Database error: {e}")
            logger.error(f"Database initialization error: {e}")

def add_sample_data():
    """Add sample data for testing"""
    # Create sample users
    user1 = User(
        name="John Doe",
        email="john@example.com",
        password_hash=generate_password_hash("password123"),
        role="user",
        phone="+1234567890"
    )
    
    runner1 = User(
        name="Mike Runner",
        email="mike@example.com",
        password_hash=generate_password_hash("password123"),
        role="runner",
        phone="+0987654321"
    )
    
    # Create admin user
    admin_user = User(
        name="Admin User",
        email="admin@boyboy.com",
        password_hash=generate_password_hash("admin123"),
        role="user",
        phone="+1111111111",
        is_admin=True
    )
    
    db.session.add(user1)
    db.session.add(runner1)
    db.session.add(admin_user)
    db.session.commit()
    
    # Create sample errands
    errand1 = Errand(
        title="Grocery Shopping",
        description="Need someone to buy groceries from Whole Foods. List will be provided.",
        location="Manhattan, NY",
        budget=25.00,
        deadline=datetime(2024, 12, 25, 18, 0),
        category="shopping",
        poster_id=user1.id
    )
    
    errand2 = Errand(
        title="Package Delivery",
        description="Need to deliver a small package to downtown office.",
        location="Financial District, NY",
        budget=15.00,
        deadline=datetime(2024, 12, 24, 17, 0),
        category="delivery",
        poster_id=user1.id
    )
    
    db.session.add(errand1)
    db.session.add(errand2)
    db.session.commit()

# PWA Routes
@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')

@app.route('/manifest.json')
def manifest():
    return app.send_static_file('manifest.json')

@app.route('/offline')
def offline():
    return render_template('offline.html')

# Home page
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    errands = Errand.query.filter_by(status='open').order_by(Errand.created_at.desc()).all()
    return render_template('index.html', name='Boy-Boy', errands=errands)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role
            session['user_email'] = user.email
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            
            # Redirect admin users to admin dashboard
            if user.is_admin or user.email == 'admin@boyboy.com':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        phone = request.form.get('phone', '')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Validate role
        if role not in ['user', 'runner']:
            flash('Invalid role selected', 'error')
            return render_template('register.html')
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password_hash=hashed_password, role=role, phone=phone)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'Registration successful! Welcome to Boy-Boy as a {role}.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Dashboard page
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if session['user_role'] == 'user':
        # User dashboard - show their posted errands
        my_errands = Errand.query.filter_by(poster_id=session['user_id']).order_by(Errand.created_at.desc()).all()
        return render_template('dashboard.html', user=user, my_errands=my_errands)
    else:
        # Runner dashboard - show available errands and their accepted errands
        available_errands = Errand.query.filter_by(status='open').order_by(Errand.created_at.desc()).all()
        my_accepted_errands = Errand.query.filter_by(runner_id=session['user_id']).order_by(Errand.created_at.desc()).all()
        return render_template('dashboard.html', user=user, available_errands=available_errands, my_accepted_errands=my_accepted_errands)

# Browse available errands (for runners)
@app.route('/browse-errands')
def browse_errands():
    if 'user_id' not in session:
        flash('Please login to browse errands', 'error')
        return redirect(url_for('login'))
    
    if session['user_role'] != 'runner':
        flash('Only runners can browse errands', 'error')
        return redirect(url_for('dashboard'))
    
    # Get filter parameters
    category = request.args.get('category', '')
    max_budget = request.args.get('max_budget', '')
    location = request.args.get('location', '')
    
    # Build query
    query = Errand.query.filter_by(status='open')
    
    if category:
        query = query.filter_by(category=category)
    if max_budget:
        try:
            query = query.filter(Errand.budget <= float(max_budget))
        except ValueError:
            flash('Invalid budget filter', 'error')
    if location:
        query = query.filter(Errand.location.ilike(f'%{location}%'))
    
    errands = query.order_by(Errand.created_at.desc()).all()
    
    return render_template('browse_errands.html', errands=errands)

# Accept an errand
@app.route('/accept-errand/<int:errand_id>')
def accept_errand(errand_id):
    if 'user_id' not in session:
        flash('Please login to accept errands', 'error')
        return redirect(url_for('login'))
    
    if session['user_role'] != 'runner':
        flash('Only runners can accept errands', 'error')
        return redirect(url_for('dashboard'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    # Check if errand is still available
    if errand.status != 'open':
        flash('This errand is no longer available', 'error')
        return redirect(url_for('browse_errands'))
    
    # Check if runner is trying to accept their own errand
    if errand.poster_id == session['user_id']:
        flash('You cannot accept your own errand', 'error')
        return redirect(url_for('browse_errands'))
    
    # Accept the errand
    errand.runner_id = session['user_id']
    errand.status = 'in_progress'
    errand.accepted_at = datetime.utcnow()
    
    db.session.commit()
    
    flash('Errand accepted successfully!', 'success')
    return redirect(url_for('dashboard'))

# Mark errand as completed
@app.route('/complete-errand/<int:errand_id>')
def complete_errand(errand_id):
    if 'user_id' not in session:
        flash('Please login to complete errands', 'error')
        return redirect(url_for('login'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    # Check if user is the runner who accepted this errand
    if errand.runner_id != session['user_id']:
        flash('You can only complete errands you have accepted', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if errand is in progress
    if errand.status != 'in_progress':
        flash('This errand cannot be completed', 'error')
        return redirect(url_for('dashboard'))
    
    # Complete the errand
    errand.status = 'completed'
    errand.completed_at = datetime.utcnow()
    
    db.session.commit()
    
    flash('Errand marked as completed!', 'success')
    return redirect(url_for('dashboard'))

# Create Errand page
@app.route('/create-errand', methods=['GET', 'POST'])
def create_errand():
    if 'user_id' not in session:
        flash('Please login to create an errand', 'error')
        return redirect(url_for('login'))
    
    if session['user_role'] != 'user':
        flash('Only users can create errands. Runners can accept errands.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            title = request.form['title']
            description = request.form['description']
            location = request.form['location']
            budget = float(request.form['budget'])
            deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%dT%H:%M')
            category = request.form.get('category', 'general')
            
            # Validate budget
            if budget <= 0:
                flash('Budget must be greater than 0', 'error')
                return render_template('create_errand.html')
            
            # Validate deadline
            if deadline <= datetime.utcnow():
                flash('Deadline must be in the future', 'error')
                return render_template('create_errand.html')
            
            new_errand = Errand(
                title=title,
                description=description,
                location=location,
                budget=budget,
                deadline=deadline,
                category=category,
                poster_id=session['user_id']
            )
            
            db.session.add(new_errand)
            db.session.commit()
            
            flash('Errand created successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except ValueError as e:
            flash('Invalid input data. Please check your entries.', 'error')
            logger.error(f"Create errand validation error: {e}")
        except Exception as e:
            flash('Error creating errand. Please try again.', 'error')
            logger.error(f"Create errand error: {e}")
    
    return render_template('create_errand.html')

# Edit Errand page
@app.route('/edit-errand/<int:errand_id>', methods=['GET', 'POST'])
def edit_errand(errand_id):
    if 'user_id' not in session:
        flash('Please login to edit an errand', 'error')
        return redirect(url_for('login'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    # Check if user owns this errand
    if errand.poster_id != session['user_id']:
        flash('You can only edit your own errands', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if errand can be edited (only open errands)
    if errand.status != 'open':
        flash('Only open errands can be edited', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            errand.title = request.form['title']
            errand.description = request.form['description']
            errand.location = request.form['location']
            errand.budget = float(request.form['budget'])
            errand.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%dT%H:%M')
            errand.category = request.form.get('category', 'general')
            
            # Validate budget
            if errand.budget <= 0:
                flash('Budget must be greater than 0', 'error')
                return render_template('edit_errand.html', errand=errand)
            
            # Validate deadline
            if errand.deadline <= datetime.utcnow():
                flash('Deadline must be in the future', 'error')
                return render_template('edit_errand.html', errand=errand)
            
            db.session.commit()
            flash('Errand updated successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except ValueError as e:
            flash('Invalid input data. Please check your entries.', 'error')
            logger.error(f"Edit errand validation error: {e}")
        except Exception as e:
            flash('Error updating errand. Please try again.', 'error')
            logger.error(f"Edit errand error: {e}")
    
    return render_template('edit_errand.html', errand=errand)

# Delete Errand route
@app.route('/delete-errand/<int:errand_id>')
def delete_errand(errand_id):
    if 'user_id' not in session:
        flash('Please login to delete an errand', 'error')
        return redirect(url_for('login'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    # Check if user owns this errand
    if errand.poster_id != session['user_id']:
        flash('You can only delete your own errands', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if errand can be deleted (only open errands)
    if errand.status != 'open':
        flash('Only open errands can be deleted', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(errand)
        db.session.commit()
        flash('Errand deleted successfully!', 'success')
    except Exception as e:
        flash('Error deleting errand. Please try again.', 'error')
        logger.error(f"Delete errand error: {e}")
    
    return redirect(url_for('dashboard'))

# Messages page
@app.route('/messages')
def messages():
    if 'user_id' not in session:
        flash('Please login to view messages', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Get all errands where user is involved (as poster or runner)
    user_errands = Errand.query.filter(
        (Errand.poster_id == user_id) | (Errand.runner_id == user_id)
    ).all()
    
    # Get unique conversations (other users you've messaged with)
    conversations = []
    for errand in user_errands:
        if errand.poster_id == user_id and errand.runner_id:
            # User is poster, runner is other party
            other_user = User.query.get(errand.runner_id)
            conversations.append({
                'errand': errand,
                'other_user': other_user,
                'user_role': 'poster'
            })
        elif errand.runner_id == user_id:
            # User is runner, poster is other party
            other_user = User.query.get(errand.poster_id)
            conversations.append({
                'errand': errand,
                'other_user': other_user,
                'user_role': 'runner'
            })
    
    return render_template('messages.html', conversations=conversations)

# Individual conversation page - FIXED SECURITY
@app.route('/messages/<int:errand_id>')
def conversation(errand_id):
    if 'user_id' not in session:
        flash('Please login to view messages', 'error')
        return redirect(url_for('login'))
    
    errand = Errand.query.get_or_404(errand_id)
    user_id = session['user_id']
    
    # ENHANCED SECURITY CHECK
    if errand.poster_id != user_id and errand.runner_id != user_id:
        flash('Access denied', 'error')
        return redirect(url_for('messages'))
    
    # Handle case where errand has no runner yet
    if not errand.runner_id and errand.poster_id != user_id:
        flash('No conversation available for this errand yet', 'error')
        return redirect(url_for('messages'))
    
    # Get the other user
    if errand.poster_id == user_id:
        other_user = User.query.get(errand.runner_id) if errand.runner_id else None
        user_role = 'poster'
    else:
        other_user = User.query.get(errand.poster_id)
        user_role = 'runner'
    
    # Get messages for this errand
    messages = Message.query.filter_by(errand_id=errand_id).order_by(Message.created_at.asc()).all()
    
    # Mark messages as read
    for message in messages:
        if message.receiver_id == user_id and not message.is_read:
            message.is_read = True
    db.session.commit()
    
    return render_template('conversation.html', 
                         errand=errand, 
                         other_user=other_user,
                         messages=messages,
                         user_role=user_role)

# Send message
@app.route('/send-message/<int:errand_id>', methods=['POST'])
def send_message(errand_id):
    if 'user_id' not in session:
        flash('Please login to send messages', 'error')
        return redirect(url_for('login'))
    
    errand = Errand.query.get_or_404(errand_id)
    user_id = session['user_id']
    
    # Check if user is part of this errand
    if errand.poster_id != user_id and errand.runner_id != user_id:
        flash('You are not part of this errand', 'error')
        return redirect(url_for('messages'))
    
    content = request.form.get('content', '').strip()
    
    if not content:
        flash('Message cannot be empty', 'error')
        return redirect(url_for('conversation', errand_id=errand_id))
    
    # Determine receiver
    if errand.poster_id == user_id:
        receiver_id = errand.runner_id
    else:
        receiver_id = errand.poster_id
    
    if not receiver_id:
        flash('No one to message for this errand yet', 'error')
        return redirect(url_for('messages'))
    
    # Create message
    new_message = Message(
        content=content,
        sender_id=user_id,
        receiver_id=receiver_id,
        errand_id=errand_id
    )
    
    try:
        db.session.add(new_message)
        db.session.commit()
        flash('Message sent!', 'success')
    except Exception as e:
        flash('Error sending message. Please try again.', 'error')
        logger.error(f"Send message error: {e}")
    
    return redirect(url_for('conversation', errand_id=errand_id))

# Get unread message count (for navbar badge)
@app.route('/unread-count')
def unread_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})
    
    count = Message.query.filter_by(
        receiver_id=session['user_id'],
        is_read=False
    ).count()
    
    return jsonify({'count': count})

# Update Profile route with IMPROVED error handling
@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Please login to update your profile', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        remove_picture = request.form.get('remove_picture')
        
        changes_made = False
        
        try:
            # Update name if provided and different
            if name and name != user.name:
                user.name = name
                changes_made = True
                session['user_name'] = name
            
            # Update phone if provided
            if phone and phone != user.phone:
                user.phone = phone
                changes_made = True
            
            # Handle profile picture upload with validation
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename != '':
                    if not allowed_file(file.filename):
                        flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF.', 'error')
                        return redirect(url_for('profile'))
                    
                    # Ensure upload directory exists
                    os.makedirs(app.config['PROFILE_PICS_FOLDER'], exist_ok=True)
                    
                    # Delete old profile picture if it's not the default
                    if user.profile_picture and user.profile_picture != 'default_avatar.png':
                        try:
                            old_picture_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], user.profile_picture)
                            if os.path.exists(old_picture_path):
                                os.remove(old_picture_path)
                        except Exception as e:
                            logger.error(f"Error removing old profile picture: {e}")
                    
                    # Save new picture
                    filename = secure_filename(f"profile_{user.id}_{datetime.utcnow().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
                    file_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], filename)
                    file.save(file_path)
                    user.profile_picture = filename
                    changes_made = True
            
            # Handle remove picture request with error handling
            if remove_picture and user.profile_picture and user.profile_picture != 'default_avatar.png':
                try:
                    old_picture_path = os.path.join(app.config['PROFILE_PICS_FOLDER'], user.profile_picture)
                    if os.path.exists(old_picture_path):
                        os.remove(old_picture_path)
                    user.profile_picture = 'default_avatar.png'
                    changes_made = True
                except Exception as e:
                    flash('Error removing profile picture', 'error')
                    logger.error(f"Error removing profile picture: {e}")
            
            # Update password if all password fields are provided
            if current_password and new_password and confirm_password:
                if not check_password_hash(user.password_hash, current_password):
                    flash('Current password is incorrect', 'error')
                    return redirect(url_for('profile'))
                
                if new_password != confirm_password:
                    flash('New passwords do not match', 'error')
                    return redirect(url_for('profile'))
                
                if check_password_hash(user.password_hash, new_password):
                    flash('New password must be different from current password', 'error')
                    return redirect(url_for('profile'))
                
                user.password_hash = generate_password_hash(new_password)
                changes_made = True
            
            if changes_made:
                db.session.commit()
                flash('Profile updated successfully!', 'success')
            else:
                flash('No changes were made', 'info')
                
        except Exception as e:
            flash('Error updating profile. Please try again.', 'error')
            logger.error(f"Profile update error: {e}")
        
        return redirect(url_for('profile'))
    
    return redirect(url_for('profile'))

# Profile page
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# Payment routes with SECURITY FIXES
@app.route('/initiate-payment/<int:errand_id>')
def initiate_payment(errand_id):
    if 'user_id' not in session:
        flash('Please login to make payment', 'error')
        return redirect(url_for('login'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    # Check if user owns this errand
    if errand.poster_id != session['user_id']:
        flash('You can only pay for your own errands', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if errand is completed
    if errand.status != 'completed':
        flash('You can only pay for completed errands', 'error')
        return redirect(url_for('dashboard'))
    
    # FIXED: Check for existing payments (pending or completed)
    existing_payment = Payment.query.filter_by(errand_id=errand_id).filter(
        Payment.status.in_(['pending', 'completed'])
    ).first()
    if existing_payment:
        if existing_payment.status == 'pending':
            flash('A payment is already pending for this errand', 'warning')
        else:
            flash('This errand has already been paid for', 'info')
        return redirect(url_for('dashboard'))
    
    return render_template('initiate_payment.html', errand=errand)

# Submit payment proof with IMPROVED validation
@app.route('/submit-payment/<int:errand_id>', methods=['POST'])
def submit_payment(errand_id):
    if 'user_id' not in session:
        flash('Please login to submit payment', 'error')
        return redirect(url_for('login'))
    
    errand = Errand.query.get_or_404(errand_id)
    
    if errand.poster_id != session['user_id']:
        flash('You can only pay for your own errands', 'error')
        return redirect(url_for('dashboard'))
    
    payment_method = request.form.get('payment_method')
    payer_phone = request.form.get('payer_phone')
    notes = request.form.get('notes', '')
    
    if not payment_method or not payer_phone:
        flash('Please fill in all required fields', 'error')
        return redirect(url_for('initiate_payment', errand_id=errand_id))
    
    # Check for existing pending payment
    existing_payment = Payment.query.filter_by(
        errand_id=errand_id, 
        status='pending'
    ).first()
    if existing_payment:
        flash('A payment is already pending for this errand', 'error')
        return redirect(url_for('dashboard'))
    
    # Handle file upload with validation
    payment_proof = None
    if 'payment_proof' in request.files:
        file = request.files['payment_proof']
        if file and file.filename != '':
            if not allowed_file(file.filename):
                flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF.', 'error')
                return redirect(url_for('initiate_payment', errand_id=errand_id))
            
            # Ensure upload directory exists
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            filename = secure_filename(f"payment_{errand_id}_{session['user_id']}_{datetime.utcnow().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            payment_proof = filename
    
    # Create payment record
    new_payment = Payment(
        amount=errand.budget,
        payment_method=payment_method,
        payer_phone=payer_phone,
        payee_phone=errand.runner.phone if errand.runner else None,  # FIXED: Use 'runner' not 'runner_user'
        notes=notes,
        payment_proof=payment_proof,
        errand_id=errand_id,
        payer_id=session['user_id'],
        payee_id=errand.runner_id,
        status='pending'
    )
    
    try:
        db.session.add(new_payment)
        db.session.commit()
        flash('Payment submitted! The runner will confirm receipt.', 'success')
    except Exception as e:
        flash('Error submitting payment. Please try again.', 'error')
        logger.error(f"Payment submission error: {e}")
    
    return redirect(url_for('dashboard'))

# Confirm payment (for runners)
@app.route('/confirm-payment/<int:payment_id>')
def confirm_payment(payment_id):
    if 'user_id' not in session:
        flash('Please login to confirm payment', 'error')
        return redirect(url_for('login'))
    
    payment = Payment.query.get_or_404(payment_id)
    
    # Check if user is the payee (runner)
    if payment.payee_id != session['user_id']:
        flash('You can only confirm payments received by you', 'error')
        return redirect(url_for('dashboard'))
    
    payment.status = 'completed'
    payment.completed_at = datetime.utcnow()
    
    # Update errand payment status
    payment.errand.payment_status = 'paid'
    
    try:
        db.session.commit()
        flash('Payment confirmed! Thank you.', 'success')
    except Exception as e:
        flash('Error confirming payment. Please try again.', 'error')
        logger.error(f"Payment confirmation error: {e}")
    
    return redirect(url_for('dashboard'))

# Cancel payment (for users)
@app.route('/cancel-payment/<int:payment_id>')
def cancel_payment(payment_id):
    if 'user_id' not in session:
        flash('Please login to cancel payment', 'error')
        return redirect(url_for('login'))
    
    payment = Payment.query.get_or_404(payment_id)
    
    # Check if user is the payer
    if payment.payer_id != session['user_id']:
        flash('You can only cancel your own payments', 'error')
        return redirect(url_for('dashboard'))
    
    payment.status = 'cancelled'
    
    try:
        db.session.commit()
        flash('Payment cancelled', 'info')
    except Exception as e:
        flash('Error cancelling payment. Please try again.', 'error')
        logger.error(f"Payment cancellation error: {e}")
    
    return redirect(url_for('dashboard'))

# ==================== ADMIN ROUTES (PROTECTED) ====================

@app.route('/admin')
@admin_required
def admin_dashboard():
    # Admin statistics
    total_users = User.query.count()
    total_errands = Errand.query.count()
    total_payments = Payment.query.count()
    total_revenue = db.session.query(db.func.sum(Payment.amount)).filter(Payment.status == 'completed').scalar() or 0
    
    # Recent activities
    recent_errands = Errand.query.order_by(Errand.created_at.desc()).limit(10).all()
    recent_payments = Payment.query.order_by(Payment.created_at.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    # Status breakdowns
    errand_statuses = db.session.query(
        Errand.status, 
        db.func.count(Errand.id)
    ).group_by(Errand.status).all()
    
    payment_statuses = db.session.query(
        Payment.status, 
        db.func.count(Payment.id)
    ).group_by(Payment.status).all()
    
    user_roles = db.session.query(
        User.role,
        db.func.count(User.id)
    ).group_by(User.role).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_errands=total_errands,
                         total_payments=total_payments,
                         total_revenue=total_revenue,
                         recent_errands=recent_errands,
                         recent_payments=recent_payments,
                         recent_users=recent_users,
                         errand_statuses=errand_statuses,
                         payment_statuses=payment_statuses,
                         user_roles=user_roles)

@app.route('/admin/users')
@admin_required
def admin_users():
    # Get filter parameters
    role = request.args.get('role', '')
    search = request.args.get('search', '')
    
    # Build query
    query = User.query
    
    if role:
        query = query.filter_by(role=role)
    if search:
        query = query.filter(
            (User.name.ilike(f'%{search}%')) | 
            (User.email.ilike(f'%{search}%'))
        )
    
    users = query.order_by(User.created_at.desc()).all()
    
    today_start = datetime.combine(datetime.now().date(), time.min)
    
    return render_template('admin/users.html', users=users, today=today_start)

@app.route('/admin/errands')
@admin_required
def admin_errands():
    # Get filter parameters
    status = request.args.get('status', '')
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    
    # Build query
    query = Errand.query
    
    if status:
        query = query.filter_by(status=status)
    if category:
        query = query.filter_by(category=category)
    if search:
        query = query.filter(
            (Errand.title.ilike(f'%{search}%')) | 
            (Errand.description.ilike(f'%{search}%')) |
            (Errand.location.ilike(f'%{search}%'))
        )
    
    errands = query.order_by(Errand.created_at.desc()).all()
    
    today_start = datetime.combine(datetime.now().date(), time.min)
    
    return render_template('admin/errands.html', errands=errands, today=today_start)

@app.route('/admin/payments')
@admin_required
def admin_payments():
    # Get filter parameters
    status = request.args.get('status', '')
    payment_method = request.args.get('payment_method', '')
    
    # Build query
    query = Payment.query
    
    if status:
        query = query.filter_by(status=status)
    if payment_method:
        query = query.filter_by(payment_method=payment_method)
    
    payments = query.order_by(Payment.created_at.desc()).all()
    
    return render_template('admin/payments.html', payments=payments)

@app.route('/admin/user/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    user_errands = Errand.query.filter_by(poster_id=user_id).order_by(Errand.created_at.desc()).all()
    runner_errands = Errand.query.filter_by(runner_id=user_id).order_by(Errand.created_at.desc()).all()
    payments_made = Payment.query.filter_by(payer_id=user_id).order_by(Payment.created_at.desc()).all()
    payments_received = Payment.query.filter_by(payee_id=user_id).order_by(Payment.created_at.desc()).all()
    
    return render_template('admin/user_detail.html',
                         user=user,
                         user_errands=user_errands,
                         runner_errands=runner_errands,
                         payments_made=payments_made,
                         payments_received=payments_received)

@app.route('/admin/errand/<int:errand_id>')
@admin_required
def admin_errand_detail(errand_id):
    errand = Errand.query.get_or_404(errand_id)
    messages = Message.query.filter_by(errand_id=errand_id).order_by(Message.created_at.asc()).all()
    payments = Payment.query.filter_by(errand_id=errand_id).order_by(Payment.created_at.desc()).all()
    
    return render_template('admin/errand_detail.html',
                         errand=errand,
                         messages=messages,
                         payments=payments)

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    # Create upload folders if they don't exist
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(PROFILE_PICS_FOLDER, exist_ok=True)
    
    # Initialize database when app starts
    init_db()
    
    # Run on local network so phone can access
    print("🚀 Starting Boy-Boy Errand App...")
    print("📱 To access from your phone:")
    print("   1. Make sure your phone is on the same WiFi")
    print("   2. Find your computer's IP address")
    print("   3. On your phone, go to: http://[YOUR-IP]:5000")
    print("   4. Add to home screen for app-like experience!")
    print("\n✨ Server running at: http://0.0.0.0:5000")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
