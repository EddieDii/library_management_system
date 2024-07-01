import re
import os
import io
import random
import string
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from config import Config
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
db.init_app(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(64), default='user')

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    pdf_data = db.Column(db.LargeBinary, nullable=False)  
    image_data = db.Column(db.LargeBinary, nullable=True)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[!@#$%^&*(),.?/:{}|<>-]", password):
        return False, "Password must contain at least one special character"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    return True, ""

def generate_verification_code(length=5):
    uppercase_letters = string.ascii_uppercase
    return ''.join(random.choice(uppercase_letters) for _ in range(length))

def send_verification_email(user_email, code):
    msg = Message('Email Verification', 
                  sender='joshua.zhaox@gmail.com', 
                  recipients=[user_email])
    msg.body = f'Your verification code is: {code}'
    mail.send(msg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html')

        if password == username:
            flash("Password can't be same with Username.")
            return render_template('register.html')
        
        if password == email:
            flash("Password can't be same with Email.")
            return render_template('register.html')

        valid, message = validate_password(password)
        if not valid:
            flash(message)
            return render_template('register.html')

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists')
            return render_template('register.html')
        
        verification_code = generate_verification_code()
        session['verification_code'] = verification_code
        session['username'] = username
        session['email'] = email
        session['password'] = password
        send_verification_email(email, verification_code)

        return redirect(url_for('register_email_verification'))
    return render_template('register.html')

@app.route('/register-email-verification')
def register_email_verification():
    return render_template('register-email-verification.html')

@app.route('/register-verify-code', methods=['POST'])
def register_verify_code():
    code = request.form['code']
    if code == session.get('verification_code'):
        username = session.get('username')
        email = session.get('email')
        password = session.get('password')

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()

        session.pop('verification_code', None)
        session.pop('username', None)
        session.pop('email', None)
        session.pop('password', None)

        return redirect(url_for('register_success'))
    else:
        flash('Invalid verification code')
        return redirect(url_for('register_email_verification'))

@app.route('/register-success')
def register_success():
    return render_template('register-success.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        session['username'] = username
        session['role'] = user.role
        
        if user.username == 'admin':
            return redirect(url_for('login_success'))
        else:
            verification_code = generate_verification_code()
            session['verification_code'] = verification_code
            send_verification_email(user.email, verification_code)
            return redirect(url_for('login_email_verification'))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))
    
@app.route('/login-email-verification')
def login_email_verification():
    return render_template('login-email-verification.html')
    
@app.route('/login-verify-code', methods=['POST'])
def login_verify_code():
    code = request.form['code']
    if code == session.get('verification_code'):
        return redirect(url_for('login_success'))
    else:
        flash('Invalid verification code')
        return redirect(url_for('login_email_verification'))

@app.route('/login-success')
def login_success():
    username = session.get('username')  
    return render_template('login-success.html', username=username)

@app.route('/guest-mode')
def guest_mode():
    session.clear()
    return redirect(url_for('search_books'))

@app.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    email = request.form.get('email', '')
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if user:
            verification_code = generate_verification_code()
            session['verification_code'] = verification_code
            send_verification_email(user.email, verification_code)
            flash('A reset code has been sent to your email. Use the code to reset your password.')
        else:
            flash('Email not found.')
    return render_template('request-password-reset.html', email=email)

@app.route('/verify-reset-code', methods=['POST'])
def verify_reset_code():
    reset_code = request.form['reset_code']
    email = request.form['email']
    if reset_code == session.get('verification_code'):
        user = User.query.filter_by(email=email).first()
        if user:
            return redirect(url_for('reset_password', email=email))
        else:
            flash('Email not found.')
            return render_template('request-password-reset.html', email=email)
    else:
        flash('Invalid reset code. Please try again.')
        return render_template('request-password-reset.html', email=email)

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Email not found.')
        return redirect(url_for('request_password_reset'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        valid, message = validate_password(password)
        if not valid:
            flash(message)
            return render_template('reset-password.html', email=email)

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset-password.html', email=email)
        
        if check_password_hash(user.password, password):
            flash('New password cannot be the same as the current password.')
            return render_template('reset-password.html', email=email)
        
        hash_password = generate_password_hash(password)
        user.password = hash_password
        db.session.commit()
        return redirect(url_for('password_reset_success'))
    
    return render_template('reset-password.html', email=email)

@app.route('/search')
def search():
    if 'search' not in request.args:
        return redirect(url_for('search_books', search=''))
    return render_template('search.html')

@app.route('/password-reset-success')
def password_reset_success():
    return render_template('password-reset-success.html')

def book_initialization():
    return Book.query.all()

@app.route('/search-book', methods=['GET'])
def search_books():
    search_query = request.args.get('search', '')
    if 'username' not in session:
        if search_query:
            flash('Only registered users can search for books.')
            return redirect(url_for('search_books'))
        else:   
            books = book_initialization()
    else:
        if search_query:
            books = Book.query.filter(Book.title.contains(search_query)).all()
        else:
            books = book_initialization()
    return render_template('search.html', books=books)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Logged out successfully')
    return redirect(url_for('index'))

@app.route('/book/<int:book_id>')
def book_detail(book_id):
     if 'username' not in session:
        flash('Please login to see the book details.')
        return redirect(url_for('search_books'))
     else:
        book = Book.query.get_or_404(book_id)
        return render_template('book_detail.html', book=book)


@app.route('/upload-book', methods=['GET', 'POST'])
def upload_book():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Only admin can upload book.')
        return redirect(url_for('search_books'))

    if request.method == 'POST':
        title = request.form.get('title')
        author = request.form.get('author')
        category = request.form.get('category')
        bio = request.form.get('bio')
        pdf_file = request.files.get('pdf')
        image_file = request.files.get('image')

        if not title or not author or not category or not pdf_file or not image_file:
            flash('Title, author, category, PDF, and image are required.')
            return redirect(url_for('upload_book'))

        pdf_data = pdf_file.read()
        image_data = image_file.read()

        new_book = Book(
            title=title, 
            author=author, 
            category=category, 
            bio=bio, 
            pdf_data=pdf_data, 
            image_data=image_data
        )
        db.session.add(new_book)
        db.session.commit()
        flash('Book uploaded successfully')
        return redirect(url_for('search_books'))
    
    return render_template('upload_book.html')

@app.route('/delete-book/<int:book_id>', methods=['GET'])
def delete_book(book_id):
    if 'username' not in session or session.get('role') != 'admin':
        flash('Only admin can delete books.')
        return redirect(url_for('book_detail', book_id=book_id))

    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    flash('Book deleted successfully')
    return redirect(url_for('search_books'))


@app.route('/pdf/<int:book_id>')
def get_pdf(book_id):
    if 'username' not in session:
        flash('Only user can download a book, please login.')
        return redirect(url_for('book_detail', book_id=book_id))
    else:
        book = Book.query.get_or_404(book_id)
        return send_file(io.BytesIO(book.pdf_data), attachment_filename=f"{book.title}.pdf", as_attachment=True)

@app.route('/image/<int:book_id>')
def get_image(book_id):
    book = Book.query.get_or_404(book_id)
    return send_file(io.BytesIO(book.image_data), mimetype='image/jpeg')


if __name__ == '__main__':
    app.run(debug=True)