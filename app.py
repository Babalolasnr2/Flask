from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password FROM users WHERE username = ? OR email = ?', (username, username))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            
            if remember:
                session.permanent = True
            else:
                session.permanent = False
                
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template_string(HTML_TEMPLATE, form_type='login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        if not email or '@' not in email:
            errors.append('Please enter a valid email address')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters long')
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            try:
                hashed_password = generate_password_hash(password)
                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                              (username, email, hashed_password))
                conn.commit()
                conn.close()
                
                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username or email already exists', 'error')
    
    return render_template_string(HTML_TEMPLATE, form_type='signup')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE, username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/api/check-username', methods=['POST'])
def check_username():
    data = request.get_json()
    username = data.get('username', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    
    return json.dumps({'available': not exists})

@app.route('/api/check-email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email', '')
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    exists = cursor.fetchone() is not None
    conn.close()
    
    return json.dumps({'available': not exists})

# HTML Templates
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% if form_type == 'login' %}Login{% else %}Sign Up{% endif %} - Beautiful Auth</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            display: flex;
            width: 100%;
            max-width: 1000px;
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        }
        
        .welcome-section {
            flex: 1;
            background: linear-gradient(to bottom right, #6a11cb, #2575fc);
            color: white;
            padding: 60px 40px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
        }
        
        .welcome-section h1 {
            font-size: 2.8rem;
            margin-bottom: 20px;
            font-weight: 700;
        }
        
        .welcome-section p {
            font-size: 1.1rem;
            line-height: 1.6;
            opacity: 0.9;
            margin-bottom: 30px;
        }
        
        .welcome-section .icon {
            font-size: 5rem;
            margin-bottom: 30px;
            opacity: 0.9;
        }
        
        .form-section {
            flex: 1;
            padding: 60px 50px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .form-header {
            margin-bottom: 40px;
        }
        
        .form-header h2 {
            color: #333;
            font-size: 2.2rem;
            margin-bottom: 10px;
        }
        
        .form-header p {
            color: #666;
            font-size: 1rem;
        }
        
        .form-group {
            margin-bottom: 25px;
            position: relative;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 0.95rem;
        }
        
        .input-with-icon {
            position: relative;
        }
        
        .input-with-icon i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #6a11cb;
            font-size: 1.1rem;
        }
        
        .form-control {
            width: 100%;
            padding: 15px 15px 15px 45px;
            border: 2px solid #e1e1e1;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            border-color: #6a11cb;
            outline: none;
            box-shadow: 0 0 0 3px rgba(106, 17, 203, 0.1);
        }
        
        .password-toggle {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #777;
            cursor: pointer;
            font-size: 1.1rem;
        }
        
        .remember-forgot {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }
        
        .checkbox-container {
            display: flex;
            align-items: center;
        }
        
        .checkbox-container input {
            margin-right: 8px;
            accent-color: #6a11cb;
        }
        
        .forgot-password {
            color: #6a11cb;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .forgot-password:hover {
            color: #2575fc;
            text-decoration: underline;
        }
        
        .btn {
            display: block;
            width: 100%;
            padding: 16px;
            background: linear-gradient(to right, #6a11cb, #2575fc);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(106, 17, 203, 0.2);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .switch-form {
            text-align: center;
            margin-top: 30px;
            color: #666;
        }
        
        .switch-form a {
            color: #6a11cb;
            text-decoration: none;
            font-weight: 600;
            margin-left: 5px;
        }
        
        .switch-form a:hover {
            text-decoration: underline;
        }
        
        .messages {
            margin-bottom: 25px;
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
            font-weight: 500;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .alert-error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .alert-info {
            background-color: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }
        
        .alert-warning {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .validation-message {
            font-size: 0.85rem;
            margin-top: 5px;
            display: flex;
            align-items: center;
        }
        
        .valid {
            color: #28a745;
        }
        
        .invalid {
            color: #dc3545;
        }
        
        @media (max-width: 768px) {
            .container {
                flex-direction: column;
                max-width: 500px;
            }
            
            .welcome-section {
                padding: 40px 30px;
            }
            
            .welcome-section h1 {
                font-size: 2.2rem;
            }
            
            .form-section {
                padding: 40px 30px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="welcome-section">
            <div class="icon">
                {% if form_type == 'login' %}
                <i class="fas fa-lock"></i>
                {% else %}
                <i class="fas fa-user-plus"></i>
                {% endif %}
            </div>
            <h1>{% if form_type == 'login' %}Welcome Back{% else %}Join Us{% endif %}</h1>
            <p>
                {% if form_type == 'login' %}
                Sign in to access your personalized dashboard and manage your account.
                {% else %}
                Create an account to unlock exclusive features and connect with our community.
                {% endif %}
            </p>
            <div style="margin-top: 20px;">
                <p>Demo Credentials:</p>
                <p>Username: demo</p>
                <p>Password: demo123</p>
            </div>
        </div>
        
        <div class="form-section">
            <div class="form-header">
                <h2>{% if form_type == 'login' %}Sign In{% else %}Create Account{% endif %}</h2>
                <p>{% if form_type == 'login' %}Enter your credentials to access your account{% else %}Fill in your details to create a new account{% endif %}</p>
            </div>
            
            <div class="messages">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
            </div>
            
            {% if form_type == 'login' %}
            <form method="POST" action="{{ url_for('login') }}" id="loginForm">
                <div class="form-group">
                    <label for="username">Username or Email</label>
                    <div class="input-with-icon">
                        <i class="fas fa-user"></i>
                        <input type="text" id="username" name="username" class="form-control" placeholder="Enter your username or email" required>
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="password" name="password" class="form-control" placeholder="Enter your password" required>
                        <button type="button" class="password-toggle" id="togglePassword">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                
                <div class="remember-forgot">
                    <div class="checkbox-container">
                        <input type="checkbox" id="remember" name="remember">
                        <label for="remember">Remember me</label>
                    </div>
                    <a href="#" class="forgot-password">Forgot password?</a>
                </div>
                
                <button type="submit" class="btn">Sign In</button>
                
                <div class="switch-form">
                    Don't have an account? <a href="{{ url_for('signup') }}">Sign up here</a>
                </div>
            </form>
            {% else %}
            <form method="POST" action="{{ url_for('signup') }}" id="signupForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <div class="input-with-icon">
                        <i class="fas fa-user"></i>
                        <input type="text" id="username" name="username" class="form-control" placeholder="Choose a username" required>
                    </div>
                    <div class="validation-message" id="username-validation"></div>
                </div>
                
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <div class="input-with-icon">
                        <i class="fas fa-envelope"></i>
                        <input type="email" id="email" name="email" class="form-control" placeholder="Enter your email" required>
                    </div>
                    <div class="validation-message" id="email-validation"></div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="password" name="password" class="form-control" placeholder="Create a password" required>
                        <button type="button" class="password-toggle" id="togglePassword">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div class="validation-message" id="password-validation"></div>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <div class="input-with-icon">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="confirm_password" name="confirm_password" class="form-control" placeholder="Confirm your password" required>
                        <button type="button" class="password-toggle" id="toggleConfirmPassword">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                    <div class="validation-message" id="confirm-password-validation"></div>
                </div>
                
                <button type="submit" class="btn">Create Account</button>
                
                <div class="switch-form">
                    Already have an account? <a href="{{ url_for('login') }}">Sign in here</a>
                </div>
            </form>
            {% endif %}
        </div>
    </div>
    
    <script>
        // Toggle password visibility
        document.addEventListener('DOMContentLoaded', function() {
            const togglePassword = document.getElementById('togglePassword');
            const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');
            const passwordInput = document.getElementById('password');
            const confirmPasswordInput = document.getElementById('confirm_password');
            
            if (togglePassword && passwordInput) {
                togglePassword.addEventListener('click', function() {
                    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                    passwordInput.setAttribute('type', type);
                    this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
                });
            }
            
            if (toggleConfirmPassword && confirmPasswordInput) {
                toggleConfirmPassword.addEventListener('click', function() {
                    const type = confirmPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                    confirmPasswordInput.setAttribute('type', type);
                    this.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
                });
            }
            
            // Username validation for signup form
            const usernameInput = document.getElementById('username');
            if (usernameInput && window.location.pathname === '/signup') {
                usernameInput.addEventListener('blur', function() {
                    const username = this.value;
                    const validationElement = document.getElementById('username-validation');
                    
                    if (username.length < 3) {
                        validationElement.innerHTML = '<i class="fas fa-times-circle invalid"></i> Username must be at least 3 characters';
                        validationElement.className = 'validation-message invalid';
                        return;
                    }
                    
                    // Check username availability via API
                    fetch('/api/check-username', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ username: username })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.available) {
                            validationElement.innerHTML = '<i class="fas fa-check-circle valid"></i> Username is available';
                            validationElement.className = 'validation-message valid';
                        } else {
                            validationElement.innerHTML = '<i class="fas fa-times-circle invalid"></i> Username is already taken';
                            validationElement.className = 'validation-message invalid';
                        }
                    });
                });
            }
            
            // Email validation for signup form
            const emailInput = document.getElementById('email');
            if (emailInput && window.location.pathname === '/signup') {
                emailInput.addEventListener('blur', function() {
                    const email = this.value;
                    const validationElement = document.getElementById('email-validation');
                    
                    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                    if (!emailRegex.test(email)) {
                        validationElement.innerHTML = '<i class="fas fa-times-circle invalid"></i> Please enter a valid email';
                        validationElement.className = 'validation-message invalid';
                        return;
                    }
                    
                    // Check email availability via API
                    fetch('/api/check-email', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ email: email })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.available) {
                            validationElement.innerHTML = '<i class="fas fa-check-circle valid"></i> Email is available';
                            validationElement.className = 'validation-message valid';
                        } else {
                            validationElement.innerHTML = '<i class="fas fa-times-circle invalid"></i> Email is already registered';
                            validationElement.className = 'validation-message invalid';
                        }
                    });
                });
            }
            
            // Password validation for signup form
            const passwordInputSignup = document.getElementById('password');
            if (passwordInputSignup && window.location.pathname === '/signup') {
                passwordInputSignup.addEventListener('input', function() {
                    const password = this.value;
                    const validationElement = document.getElementById('password-validation');
                    
                    if (password.length < 6) {
                        validationElement.innerHTML = '<i class="fas fa-times-circle invalid"></i> Password must be at least 6 characters';
                        validationElement.className = 'validation-message invalid';
                    } else {
                        validationElement.innerHTML = '<i class="fas fa-check-circle valid"></i> Password is strong enough';
                        validationElement.className = 'validation-message valid';
                    }
                });
            }
            
            // Confirm password validation for signup form
            const confirmPasswordInputSignup = document.getElementById('confirm_password');
            if (confirmPasswordInputSignup && passwordInputSignup && window.location.pathname === '/signup') {
                confirmPasswordInputSignup.addEventListener('input', function() {
                    const password = passwordInputSignup.value;
                    const confirmPassword = this.value;
                    const validationElement = document.getElementById('confirm-password-validation');
                    
                    if (password !== confirmPassword) {
                        validationElement.innerHTML = '<i class="fas fa-times-circle invalid"></i> Passwords do not match';
                        validationElement.className = 'validation-message invalid';
                    } else {
                        validationElement.innerHTML = '<i class="fas fa-check-circle valid"></i> Passwords match';
                        validationElement.className = 'validation-message valid';
                    }
                });
            }
            
            // Form submission validation for signup
            const signupForm = document.getElementById('signupForm');
            if (signupForm) {
                signupForm.addEventListener('submit', function(event) {
                    const password = document.getElementById('password').value;
                    const confirmPassword = document.getElementById('confirm_password').value;
                    
                    if (password !== confirmPassword) {
                        event.preventDefault();
                        alert('Passwords do not match. Please fix before submitting.');
                        return false;
                    }
                    
                    return true;
                });
            }
        });
    </script>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Beautiful Auth</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .navbar {
            background: white;
            border-radius: 15px;
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }
        
        .logo {
            font-size: 1.8rem;
            font-weight: 700;
            color: #6a11cb;
            display: flex;
            align-items: center;
        }
        
        .logo i {
            margin-right: 10px;
        }
        
        .nav-links a {
            color: #555;
            text-decoration: none;
            margin-left: 25px;
            font-weight: 500;
            transition: color 0.3s;
        }
        
        .nav-links a:hover {
            color: #6a11cb;
        }
        
        .nav-links a.logout {
            color: #dc3545;
        }
        
        .nav-links a.logout:hover {
            color: #c82333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .dashboard-header {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            text-align: center;
        }
        
        .dashboard-header h1 {
            color: #333;
            font-size: 2.5rem;
            margin-bottom: 15px;
        }
        
        .dashboard-header p {
            color: #666;
            font-size: 1.2rem;
        }
        
        .welcome-message {
            background: linear-gradient(to right, #6a11cb, #2575fc);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            font-size: 1.3rem;
            text-align: center;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s;
        }
        
        .card:hover {
            transform: translateY(-5px);
        }
        
        .card i {
            font-size: 2.5rem;
            color: #6a11cb;
            margin-bottom: 20px;
        }
        
        .card h3 {
            color: #333;
            font-size: 1.5rem;
            margin-bottom: 15px;
        }
        
        .card p {
            color: #666;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        
        .btn {
            display: inline-block;
            padding: 12px 25px;
            background: linear-gradient(to right, #6a11cb, #2575fc);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(106, 17, 203, 0.2);
        }
        
        .footer {
            text-align: center;
            color: white;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .messages {
            margin-bottom: 25px;
        }
        
        .alert {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
            font-weight: 500;
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        @media (max-width: 768px) {
            .navbar {
                flex-direction: column;
                padding: 20px;
            }
            
            .nav-links {
                margin-top: 20px;
                display: flex;
                flex-wrap: wrap;
                justify-content: center;
            }
            
            .nav-links a {
                margin: 5px 10px;
            }
            
            .dashboard-header {
                padding: 30px 20px;
            }
            
            .dashboard-header h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <nav class="navbar">
            <div class="logo">
                <i class="fas fa-lock"></i>
                SecureApp
            </div>
            <div class="nav-links">
                <a href="#"><i class="fas fa-home"></i> Home</a>
                <a href="#"><i class="fas fa-user"></i> Profile</a>
                <a href="#"><i class="fas fa-cog"></i> Settings</a>
                <a href="{{ url_for('logout') }}" class="logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
            </div>
        </nav>
        
        <div class="messages">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
        </div>
        
        <div class="dashboard-header">
            <h1>Welcome to Your Dashboard, {{ username }}!</h1>
            <p>You have successfully logged into your account.</p>
        </div>
        
        <div class="welcome-message">
            <i class="fas fa-check-circle"></i> Your account is secure and ready to use.
        </div>
        
        <div class="dashboard-grid">
            <div class="card">
                <i class="fas fa-user-circle"></i>
                <h3>Profile Management</h3>
                <p>Update your personal information, change your profile picture, and manage your account settings.</p>
                <a href="#" class="btn">Edit Profile</a>
            </div>
            
            <div class="card">
                <i class="fas fa-shield-alt"></i>
                <h3>Security Settings</h3>
                <p>Enhance your account security by changing your password and enabling two-factor authentication.</p>
                <a href="#" class="btn">Security</a>
            </div>
            
            <div class="card">
                <i class="fas fa-chart-line"></i>
                <h3>Activity Overview</h3>
                <p>View your recent account activity, login history, and monitor for any suspicious actions.</p>
                <a href="#" class="btn">View Activity</a>
            </div>
        </div>
        
        <div class="footer">
            <p>© 2023 Beautiful Auth System. All rights reserved.</p>
            <p>Logged in as: <strong>{{ username }}</strong> | <a href="{{ url_for('logout') }}" style="color: white;">Logout</a></p>
        </div>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)
