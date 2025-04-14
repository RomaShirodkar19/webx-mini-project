import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# MongoDB setup
client = MongoClient(os.getenv('MONGODB_URI'))
db = client['ecommerce']
users = db['users']
products = db['products']
carts = db['carts']

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_doc):
        self.id = str(user_doc['_id'])
        self.email = user_doc['email']
        self.role = user_doc.get('role', 'user')

@login_manager.user_loader
def load_user(user_id):
    user = users.find_one({'_id': ObjectId(user_id)})
    return User(user) if user else None

# ----------------- Utility Functions ----------------- #
def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field.capitalize()}: {error}", 'error')

# ----------------- Routes ----------------- #

@app.route('/')
def index():
    all_products = list(products.find())
    return render_template('index.html', products=all_products)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return redirect(url_for('signup'))
            
        if users.find_one({'email': email}):
            flash('Email already exists', 'error')
            return redirect(url_for('signup'))
            
        users.insert_one({
            'email': email,
            'password': generate_password_hash(password),
            'role': 'user'
        })
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        user = users.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            login_user(User(user))
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
            
        flash('Invalid email or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/add_to_cart/<product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = products.find_one({'_id': ObjectId(product_id)})
    if not product:
        flash('Product not found', 'error')
        return redirect(url_for('index'))

    # Check if the product is already in the user's cart
    existing = carts.find_one({'user_id': current_user.id, 'product_id': product_id})
    
    if existing:
        carts.update_one(
            {'_id': existing['_id']},
            {'$inc': {'quantity': 1}}
        )
    else:
        carts.insert_one({
            'user_id': current_user.id,
            'product_id': product_id,
            'quantity': 1
        })

    flash('Product added to cart!', 'success')
    return redirect(url_for('index'))


@app.route('/cart')
@login_required
def cart():
    cart_items = list(carts.find({'user_id': current_user.id}))
    detailed_cart = []

    for item in cart_items:
        product = products.find_one({'_id': ObjectId(item['product_id'])})
        if product:
            detailed_cart.append({
                'cart_id': str(item['_id']),
                'product_id': str(product['_id']),
                'name': product['name'],
                'price': product['price'],
                'image_url': product.get('image_url', ''),
                'quantity': item['quantity'],
                'total': round(product['price'] * item['quantity'], 2)
            })

    total_amount = sum(item['total'] for item in detailed_cart)
    return render_template('cart.html', cart_items=detailed_cart, total=total_amount)

@app.route('/update_cart/<cart_id>', methods=['POST'])
@login_required
def update_cart(cart_id):
    new_quantity = int(request.form.get('quantity', 1))
    if new_quantity < 1:
        carts.delete_one({'_id': ObjectId(cart_id)})
    else:
        carts.update_one({'_id': ObjectId(cart_id)}, {'$set': {'quantity': new_quantity}})
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<cart_id>')
@login_required
def remove_from_cart(cart_id):
    carts.delete_one({'_id': ObjectId(cart_id)})
    flash('Item removed from cart.', 'info')
    return redirect(url_for('cart'))




# ---------- Admin-only Product Routes ---------- #

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            products.insert_one({
                'name': request.form.get('name', '').strip(),
                'price': float(request.form.get('price', 0)),
                'desc': request.form.get('desc', '').strip(),
                'image_url': request.form.get('image_url', '').strip()
            })
            flash('Product added successfully!', 'success')
            return redirect(url_for('index'))
        except ValueError:
            flash('Invalid price format', 'error')
            
    return render_template('add_product.html')

@app.route('/edit/<product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('index'))
        
    product = products.find_one({'_id': ObjectId(product_id)})
    if not product:
        flash('Product not found', 'error')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            products.update_one(
                {'_id': ObjectId(product_id)},
                {'$set': {
                    'name': request.form.get('name', '').strip(),
                    'price': float(request.form.get('price', 0)),
                    'desc': request.form.get('desc', '').strip(),
                    'image_url': request.form.get('image_url', '').strip()
                }}
            )
            flash('Product updated successfully!', 'success')
            return redirect(url_for('index'))
        except ValueError:
            flash('Invalid price format', 'error')
            
    return render_template('edit_product.html', product=product)

@app.route('/delete/<product_id>')
@login_required
def delete_product(product_id):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('index'))
        
    result = products.delete_one({'_id': ObjectId(product_id)})
    if result.deleted_count:
        flash('Product deleted successfully', 'success')
    else:
        flash('Product not found', 'error')
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')