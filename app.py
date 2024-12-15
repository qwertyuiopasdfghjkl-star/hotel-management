from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hotel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Rate limiter for security
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Add CSRF token to all responses
@app.after_request
def add_csrf_token(response):
    if 'text/html' in response.content_type:
        response.set_cookie('csrf_token', generate_csrf())
    return response

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    bookings = db.relationship('Booking', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_number = db.Column(db.String(10), unique=True, nullable=False)
    room_type = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text)
    amenities = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    bookings = db.relationship('Booking', backref='room', lazy=True)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    check_in = db.Column(db.DateTime, nullable=False)
    check_out = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')  # active, completed, cancelled
    total_price = db.Column(db.Float)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need to be logged in as an admin to access this page.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin():
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username, is_admin=True).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully as admin!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    rooms = Room.query.all()
    bookings = Booking.query.all()
    return render_template('admin_dashboard.html', rooms=rooms, bookings=bookings)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('admin_users'))
        
    try:
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            flash('Cannot delete admin user', 'error')
            return redirect(url_for('admin_users'))
            
        # Delete user's bookings first
        Booking.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user: ' + str(e), 'error')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/rooms')
@login_required
@admin_required
def admin_rooms():
    rooms = Room.query.all()
    return render_template('admin/rooms.html', rooms=rooms)

@app.route('/admin/add_room', methods=['POST'])
@login_required
@admin_required
def add_room():
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('admin_dashboard'))
        
    try:
        room = Room(
            room_number=request.form['room_number'],
            room_type=request.form['room_type'],
            price=float(request.form['price']),
            description=request.form.get('description', ''),
            amenities=request.form.get('amenities', ''),
            is_available=True
        )
        db.session.add(room)
        db.session.commit()
        flash('Room added successfully', 'success')
    except ValueError:
        flash('Invalid price value', 'error')
    except Exception as e:
        db.session.rollback()
        flash('Error adding room: ' + str(e), 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_room/<int:room_id>', methods=['POST'])
@login_required
@admin_required
def edit_room(room_id):
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('admin_dashboard'))
        
    try:
        room = Room.query.get_or_404(room_id)
        room.room_type = request.form['room_type']
        room.price = float(request.form['price'])
        room.description = request.form.get('description', '')
        room.amenities = request.form.get('amenities', '')
        
        db.session.commit()
        flash('Room updated successfully', 'success')
    except ValueError:
        flash('Invalid price value', 'error')
    except Exception as e:
        db.session.rollback()
        flash('Error updating room: ' + str(e), 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_room/<int:room_id>', methods=['POST'])
@login_required
@admin_required
def delete_room(room_id):
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('admin_dashboard'))
        
    try:
        room = Room.query.get_or_404(room_id)
        db.session.delete(room)
        db.session.commit()
        flash('Room deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting room: ' + str(e), 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")

def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            phone = request.form.get('phone')
            address = request.form.get('address')
            
            # Validate required fields
            if not all([username, email, password, phone, address]):
                flash('All fields are required', 'error')
                return redirect(url_for('register'))
            
            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'error')
                return redirect(url_for('register'))
                
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
                
            user = User(
                username=username,
                email=email,
                phone=phone,
                address=address
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get user's bookings
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.created_at.desc()).all()
    return render_template('dashboard.html', bookings=bookings)

@app.route('/rooms')
@login_required
def view_rooms():
    rooms = Room.query.filter_by(is_available=True).all()
    return render_template('rooms.html', rooms=rooms)

@app.route('/book/<int:room_id>', methods=['POST'])
@login_required
def book_room(room_id):
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('view_rooms'))
        
    try:
        room = Room.query.get_or_404(room_id)
        if not room.is_available:
            flash('Room is not available', 'error')
            return redirect(url_for('view_rooms'))
            
        check_in = datetime.strptime(request.form.get('check_in'), '%Y-%m-%d')
        check_out = datetime.strptime(request.form.get('check_out'), '%Y-%m-%d')
        
        # Validate dates
        if check_in >= check_out:
            flash('Check-out date must be after check-in date', 'error')
            return redirect(url_for('view_rooms'))
            
        # Calculate total price
        days = (check_out - check_in).days
        total_price = room.price * days
        
        booking = Booking(
            user_id=current_user.id,
            room_id=room_id,
            check_in=check_in,
            check_out=check_out,
            total_price=total_price,
            status='active'
        )
        
        room.is_available = False
        db.session.add(booking)
        db.session.commit()
        
        flash('Room booked successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except ValueError:
        flash('Invalid date format', 'error')
    except Exception as e:
        db.session.rollback()
        flash('Error booking room: ' + str(e), 'error')
    
    return redirect(url_for('view_rooms'))

@app.route('/bookings/cancel/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    if not request.form.get('csrf_token'):
        flash('CSRF token missing', 'error')
        return redirect(url_for('dashboard'))
        
    try:
        booking = Booking.query.get_or_404(booking_id)
        
        # Verify booking belongs to current user
        if booking.user_id != current_user.id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('dashboard'))
            
        booking.status = 'cancelled'
        booking.room.is_available = True
        db.session.commit()
        
        flash('Booking cancelled successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error cancelling booking: ' + str(e), 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
