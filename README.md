# Hotel Management System

A Flask-based Hotel Management System with user and admin roles, secure authentication, and booking management.

## Features

- User Authentication (Login, Register)
- Role-based Access Control (Admin/User)
- Room Management (CRUD operations)
- Booking Management
- Secure against XSS, CSRF, and Rate Limiting
- Modern Bootstrap UI

## Security Features

- CSRF Protection using Flask-WTF
- Password Hashing using Werkzeug
- Rate Limiting using Flask-Limiter
- Session Management using Flask-Login
- Sanitization
- Secure Password Storage

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

## Default Admin Creation

To create an admin user, use the Flask shell:
```python
from app import app, db, User
with app.app_context():
    admin = User(username='admin', email='admin@example.com', is_admin=True)
    admin.password_hash = generate_password_hash('admin123')
    db.session.add(admin)
    db.session.commit()
```

## Usage

1. Admin Dashboard:
   - Manage rooms (Add, Edit, Delete)
   - View all bookings
   - Monitor system activity

2. User Dashboard:
   - View available rooms
   - Make bookings
   - View booking history

## Database

The system uses SQLite database with the following models:
- User (for authentication and user management)
- Room (for room management)
- Booking (for booking management)

## Security Notes

- Built-in CSRF protection for all forms
- Rate limiting on login and registration endpoints
- Secure password hashing
- Input validation and sanitization
- Session management
