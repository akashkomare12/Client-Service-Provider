# 🛠️ Service Marketplace Web App

A full-featured service marketplace web application built using **Flask**, where clients can book services, providers can manage requests, and admins can oversee users, providers, and service activity.

---

## 🚀 Features

### 👤 User Roles
- **Client**:
  - Register/login, request services, track service status
  - Rate and review completed services

- **Service Provider**:
  - Register/login, set service type, rate & description
  - Manage incoming requests (accept, complete, cancel)

- **Admin**:
  - View, add, update, or delete users
  - Manage service providers
  - Track and update service requests

---

## 🏗️ Tech Stack

- **Backend**: Flask, SQLAlchemy
- **Database**: SQLite (can be replaced with PostgreSQL or MySQL)
- **Frontend**: Bootstrap 5, Jinja2 templates
- **Authentication**: Session-based login with hashed passwords

---

## 🧾 Models

- `User`: Stores user credentials and roles (`client`, `provider`, `admin`)
- `ServiceProvider`: Extended profile for providers
- `ServiceRequest`: Service booking records
- `Rating`: Client feedback and star ratings

---

## 📁 Folder Structure

```
project/
│
├── app.py                 # Main Flask application
├── service_app.db         # SQLite database
├── templates/
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── client/
│   │   └── dashboard.html
│   ├── provider/
│   │   └── dashboard.html
│   └── admin/
│       └── dashboard.html
└── static/                # (Optional) Static files like CSS, JS, images
```

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/akashkomare12/Client-Service-Provider.git
cd service-marketplace-app
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the App

```bash
python app.py
```

Visit [http://localhost:5000](http://localhost:5000)

---

## 🛡️ Admin Access

To create an admin user:

```python
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
```

Login with:
- Username: `admin`
- Password: `admin123`

---

## ✅ To-Do / Future Enhancements

- Add pagination for service providers
- Real-time notifications via WebSockets
- Profile picture uploads for users
- Email verification and password reset

---

## 📄 License

This project is licensed under the MIT License.  
Feel free to use, modify, and share with credit.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you’d like to change.

---

## 💬 Contact

For questions or support, feel free to reach out at:  
📧 [akashkomare12@gmail.com](mailto:akashkomare12@gmail.com)

