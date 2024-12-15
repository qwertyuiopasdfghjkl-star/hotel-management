from app import app, db, User

def create_admin():
    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print("Admin user already exists!")
            return
            
        # Create new admin user
        admin = User(
            username='admin',
            email='admin@hotel.com',
            phone='1234567890',
            address='Hotel Address',
            is_admin=True
        )
        admin.set_password('admin123')  # Change this to a secure password
        
        try:
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {str(e)}")

if __name__ == '__main__':
    create_admin()
