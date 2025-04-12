from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User(
        username="admin",
        email="admin@example.com",
        password=generate_password_hash("admin123"),
        role="admin",
        active=True
    )
    db.session.add(admin)
    db.session.commit()
    print("Admin user created successfully!")
