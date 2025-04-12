# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///service_app.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
# migrate = Migrate(app, db)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'client', 'provider', 'admin'
    active = db.Column(db.Boolean, default=True)  
  
    
class ServiceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('service_provider.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('service_request.id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('service_provider.id'), nullable=False)
    stars = db.Column(db.Integer, nullable=False)  # 1-5 stars
    feedback = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Update ServiceProvider model to include average rating
class ServiceProvider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    service_type = db.Column(db.String(50), nullable=False)  # 'electrician', 'plumber', etc.
    rate = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    avg_rating = db.Column(db.Float, default=0)  # Average rating
    total_ratings = db.Column(db.Integer, default=0)
                              
# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # Check if user is active
            if not getattr(user, 'active', True):  # Default to True if column doesn't exist yet
                flash('Your account has been deactivated. Please contact an administrator.')
                return render_template('login.html')
                
            session['user_id'] = user.id
            session['role'] = user.role
            
            if user.role == 'client':
                return redirect(url_for('client_dashboard'))
            elif user.role == 'provider':
                return redirect(url_for('provider_dashboard'))
            elif user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')
        
        hashed_password = generate_password_hash(password)
        
        new_user = User(username=username, password=hashed_password, email=email, role=role)
        db.session.add(new_user)
        
        if role == 'provider':
            service_type = request.form.get('service_type')
            rate = float(request.form.get('rate'))
            description = request.form.get('description')
            
            db.session.flush()  # Get the user ID
            
            new_provider = ServiceProvider(
                user_id=new_user.id,
                service_type=service_type,
                rate=rate,
                description=description
            )
            db.session.add(new_provider)
        
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))



@app.route('/client/request_service/<int:provider_id>', methods=['GET', 'POST'])
def request_service(provider_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        description = request.form.get('description')
        
        new_request = ServiceRequest(
            client_id=session['user_id'],
            provider_id=provider_id,
            description=description
        )
        
        db.session.add(new_request)
        db.session.commit()
        
        flash('Service request submitted successfully!')
        return redirect(url_for('client_dashboard'))
    
    provider = ServiceProvider.query.get_or_404(provider_id)
    return render_template('client/request_service.html', provider=provider)

@app.route('/client/edit_request/<int:request_id>', methods=['GET', 'POST'])
def edit_request(request_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))
    
    request_item = ServiceRequest.query.get_or_404(request_id)
    
    if request_item.client_id != session['user_id']:
        flash('Unauthorized access')
        return redirect(url_for('client_dashboard'))
    
    if request.method == 'POST':
        request_item.description = request.form.get('description')
        
        if request_item.status == 'pending':
            action = request.form.get('action')
            if action == 'cancel':
                request_item.status = 'cancelled'
        
        db.session.commit()
        flash('Request updated successfully!')
        return redirect(url_for('client_dashboard'))
    
    return render_template('client/edit_request.html', request=request_item)

# Provider Routes
@app.route('/provider/dashboard')
def provider_dashboard():
    if 'user_id' not in session or session['role'] != 'provider':
        return redirect(url_for('login'))
    
    provider = ServiceProvider.query.filter_by(user_id=session['user_id']).first()
    
    if not provider:
        flash('Provider profile not found!')
        return redirect(url_for('logout'))
    
    requests = ServiceRequest.query.filter_by(provider_id=provider.id).all()
    
    return render_template('provider/dashboard.html', provider=provider, requests=requests)

@app.route('/provider/update_request/<int:request_id>', methods=['POST'])
def update_request(request_id):
    if 'user_id' not in session or session['role'] != 'provider':
        return redirect(url_for('login'))
    
    provider = ServiceProvider.query.filter_by(user_id=session['user_id']).first()
    request_item = ServiceRequest.query.get_or_404(request_id)
    
    if request_item.provider_id != provider.id:
        flash('Unauthorized access')
        return redirect(url_for('provider_dashboard'))
    
    action = request.form.get('action')
    
    if action == 'accept' and request_item.status == 'pending':
        request_item.status = 'accepted'
    elif action == 'complete' and request_item.status == 'accepted':
        request_item.status = 'completed'
    elif action == 'cancel' and request_item.status in ['pending', 'accepted']:
        request_item.status = 'cancelled'
    
    db.session.commit()
    flash('Request updated successfully!')
    return redirect(url_for('provider_dashboard'))

# Admin Routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    users = User.query.all()
    providers = ServiceProvider.query.all()
    requests = ServiceRequest.query.all()
    
    return render_template('admin/dashboard.html', users=users, providers=providers, requests=requests)

@app.route('/admin/create_user', methods=['POST'])
def create_user():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    role = request.form.get('role')
    
    # Check if username or email already exists
    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash('Username or email already exists!')
        return redirect(url_for('admin_dashboard'))
    
    # Create new user
    hashed_password = generate_password_hash(password)
    new_user = User(
        username=username, 
        password=hashed_password, 
        email=email, 
        role=role, 
        active=True
    )
    db.session.add(new_user)
    
    # If the user is a provider, create provider profile
    if role == 'provider':
        service_type = request.form.get('service_type')
        rate = float(request.form.get('rate', 0))
        description = request.form.get('description', '')
        
        # We need to flush to get the user ID
        db.session.flush()
        
        new_provider = ServiceProvider(
            user_id=new_user.id,
            service_type=service_type,
            rate=rate,
            description=description,
            avg_rating=0,
            total_ratings=0
        )
        db.session.add(new_provider)
    
    db.session.commit()
    flash(f'User {username} created successfully!')
    return redirect(url_for('admin_dashboard'))

# Update existing user
@app.route('/admin/update_user', methods=['POST'])
def update_user():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    status = request.form.get('status') == 'active'  # Convert to boolean
    
    user = User.query.get_or_404(user_id)
    
    # Check if username or email already exists for another user
    if username != user.username:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user.id:
            flash('Username already taken!')
            return redirect(url_for('admin_dashboard'))
    
    if email != user.email:
        existing_email = User.query.filter_by(email=email).first()
        if existing_email and existing_email.id != user.id:
            flash('Email already in use!')
            return redirect(url_for('admin_dashboard'))
    
    # Update user details
    user.username = username
    user.email = email
    user.active = status
    
    # Update password if provided
    if password and password.strip():
        user.password = generate_password_hash(password)
    
    db.session.commit()
    flash(f'User {username} updated successfully!')
    return redirect(url_for('admin_dashboard'))

# Delete user
@app.route('/admin/delete_user', methods=['POST'])
def delete_user():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    user = User.query.get_or_404(user_id)
    
    # Get provider profile if exists
    provider = ServiceProvider.query.filter_by(user_id=user_id).first()
    
    # Delete associated service requests
    if provider:
        # Delete ratings for service requests by this provider
        provider_requests = ServiceRequest.query.filter_by(provider_id=provider.id).all()
        for req in provider_requests:
            Rating.query.filter_by(request_id=req.id).delete()
        
        # Delete service requests
        ServiceRequest.query.filter_by(provider_id=provider.id).delete()
        
        # Delete provider profile
        db.session.delete(provider)
    
    # Delete client service requests and ratings
    client_requests = ServiceRequest.query.filter_by(client_id=user_id).all()
    for req in client_requests:
        Rating.query.filter_by(request_id=req.id).delete()
    
    ServiceRequest.query.filter_by(client_id=user_id).delete()
    Rating.query.filter_by(client_id=user_id).delete()
    
    # Finally delete the user
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} and all associated data deleted successfully!')
    return redirect(url_for('admin_dashboard'))

# Toggle user status
@app.route('/admin/toggle_user/<int:user_id>', methods=['POST'])
def toggle_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(user_id)
    
    # Toggle the active status
    user.active = not user.active
    db.session.commit()
    
    status = "activated" if user.active else "deactivated"
    flash(f'User {user.username} {status} successfully!')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_request', methods=['POST'])
def admin_update_request():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    request_id = request.form.get('request_id')
    status = request.form.get('status')
    notes = request.form.get('notes', '')
    
    service_request = ServiceRequest.query.get_or_404(request_id)
    service_request.status = status
    
    # In a real app, you might want to store the admin notes somewhere
    # For example, you could add an admin_notes column to the ServiceRequest model
    
    db.session.commit()
    flash(f'Service request #{request_id} updated to {status}!')
    return redirect(url_for('admin_dashboard'))


# Rating system routes
@app.route('/client/rate_service/<int:request_id>', methods=['GET', 'POST'])
def rate_service(request_id):
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))
    
    request_item = ServiceRequest.query.get_or_404(request_id)
    
    # Check if this is the client's request and if it's completed
    if request_item.client_id != session['user_id'] or request_item.status != 'completed':
        flash('You can only rate completed services that you requested')
        return redirect(url_for('client_dashboard'))
    
    # Check if already rated
    existing_rating = Rating.query.filter_by(request_id=request_id).first()
    if existing_rating:
        flash('You have already rated this service')
        return redirect(url_for('client_dashboard'))
    
    if request.method == 'POST':
        stars = int(request.form.get('stars', 0))
        feedback = request.form.get('feedback', '')
        
        if stars < 1 or stars > 5:
            flash('Please provide a rating between 1 and 5 stars')
            return redirect(url_for('rate_service', request_id=request_id))
        
        # Create new rating
        new_rating = Rating(
            request_id=request_id,
            client_id=session['user_id'],
            provider_id=request_item.provider_id,
            stars=stars,
            feedback=feedback
        )
        db.session.add(new_rating)
        
        # Update provider's average rating
        provider = ServiceProvider.query.get(request_item.provider_id)
        # Ensure avg_rating and total_ratings have valid values
        if provider.avg_rating is None:
            provider.avg_rating = 0
        if provider.total_ratings is None:
            provider.total_ratings = 0
    
        total_stars = provider.avg_rating * provider.total_ratings + stars
        provider.total_ratings += 1
        provider.avg_rating = total_stars / provider.total_ratings
        
        db.session.commit()
        flash('Thank you for your feedback!')
        return redirect(url_for('client_dashboard'))
    
    return render_template('client/rate_service.html', request=request_item)

# Enhanced client dashboard with filtering
@app.route('/client/dashboard')
def client_dashboard():
    if 'user_id' not in session or session['role'] != 'client':
        return redirect(url_for('login'))
    
    # Get filter parameters
    service_type = request.args.get('service_type', '')
    min_rating = request.args.get('min_rating', '')
    sort_by = request.args.get('sort_by', 'avg_rating')  # Default sort by rating
    
    # Base query
    query = ServiceProvider.query
    
    # Apply filters
    if service_type:
        query = query.filter(ServiceProvider.service_type == service_type)
    if min_rating:
        query = query.filter(ServiceProvider.avg_rating >= float(min_rating))
    
    # Apply sorting
    if sort_by == 'rate_low':
        query = query.order_by(ServiceProvider.rate.asc())
    elif sort_by == 'rate_high':
        query = query.order_by(ServiceProvider.rate.desc())
    else:  # Default: sort by rating
        query = query.order_by(ServiceProvider.avg_rating.desc())
    
    providers = query.all()
    
    # Get service types for filter dropdown
    service_types = db.session.query(ServiceProvider.service_type).distinct().all()
    service_types = [t[0] for t in service_types]
    
    # Get user's requests
    requests = ServiceRequest.query.filter_by(client_id=session['user_id']).all()
    
    # Get completed requests that haven't been rated
    completed_requests = []
    for req in requests:
        if req.status == 'completed':
            rating = Rating.query.filter_by(request_id=req.id).first()
            if not rating:
                completed_requests.append(req)
    
    return render_template('client/dashboard.html', 
                           providers=providers, 
                           requests=requests,
                           completed_requests=completed_requests,
                           service_types=service_types,
                           current_filters={
                               'service_type': service_type,
                               'min_rating': min_rating,
                               'sort_by': sort_by
                           })

# Get provider details including ratings and feedback
@app.route('/client/provider_details/<int:provider_id>')
def provider_details(provider_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    provider = ServiceProvider.query.get_or_404(provider_id)
    ratings = Rating.query.filter_by(provider_id=provider_id).order_by(Rating.created_at.desc()).all()
    
    return render_template('client/provider_details.html', provider=provider, ratings=ratings)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)