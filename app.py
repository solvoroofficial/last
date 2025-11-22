from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, UTC
import os
import json
import firebase_db
import admin_settings


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./site.db'
db = SQLAlchemy(app)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Force using Flask/SQLite as the database backend. Firebase integration
# is available in the codebase but disabled to ensure the app uses the
# local SQLAlchemy DB only.
USE_FIREBASE = False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Ensure SQLite tables exist when not using Firebase.
def _ensure_sql_tables():
    if not USE_FIREBASE:
        try:
            db.create_all()
        except Exception as e:
            try:
                app.logger.exception('Failed to create SQLite tables: %s', e)
            except Exception:
                # logging might not be available in some import contexts
                pass

# Try to register the function to run before the first request when supported;
# if that's not possible (some Flask variants/environments), call it immediately
# so tests and other import-time code see the tables.
try:
    # Flask provides `before_first_request` as a registration method
    reg = getattr(app, 'before_first_request', None)
    if callable(reg):
        reg(_ensure_sql_tables)
    else:
        # If the Flask object doesn't expose before_first_request in this
        # environment, run the creation inside an application context so
        # SQLAlchemy has access to the app configuration.
        try:
            with app.app_context():
                _ensure_sql_tables()
        except Exception:
            # If even this fails, swallow the error; the separate
            # scripts/create_tables.py can be used to create tables.
            pass
except Exception:
    # As a last resort, attempt to create tables now
    try:
        with app.app_context():
            _ensure_sql_tables()
    except Exception:
        pass


# Ensure new Product columns exist in existing SQLite table (safe ALTERs)
def _ensure_product_columns():
    try:
        from sqlalchemy import inspect, text
        insp = inspect(db.engine)
        cols = [c['name'] for c in insp.get_columns('product')]
        with db.engine.connect() as conn:
            if 'category' not in cols:
                # sqlite and others support simple ADD COLUMN
                conn.execute(text('ALTER TABLE product ADD COLUMN category VARCHAR(100)'))
            if 'show_on_homepage' not in cols:
                conn.execute(text("ALTER TABLE product ADD COLUMN show_on_homepage BOOLEAN DEFAULT 0"))
    except Exception:
        # If inspection or alters fail, ignore — app will still run but admin toggles may be unavailable.
        try:
            app.logger.debug('Product column ensure failed; may be running first time or unsupported DB.')
        except Exception:
            pass

# Try to ensure product columns after tables creation
try:
    with app.app_context():
        _ensure_product_columns()
except Exception:
    pass


# Lightweight user wrapper when using Firebase
class FirebaseUser(UserMixin):
    def __init__(self, data: dict):
        self.id = data.get('id') or data.get('email')
        self.name = data.get('name')
        self.email = data.get('email')
        self.password = data.get('password')
        self.created_at = data.get('created_at')


# ============ DATABASE MODELS ============

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    product_interest = db.Column(db.String(200))
    quantity = db.Column(db.Integer)
    company = db.Column(db.String(200))
    address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    status = db.Column(db.String(50), default='new')
    notes = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

class QuoteRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    product = db.Column(db.String(200), nullable=False)
    budget = db.Column(db.String(100))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))
    status = db.Column(db.String(50), default='pending')
    notes = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))


# ----- Products -----
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    image_path = db.Column(db.String(300))
    category = db.Column(db.String(100))
    show_on_homepage = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

# ============ LOGIN MANAGER ============

@login_manager.user_loader
def load_user(user_id):
    if USE_FIREBASE:
        # user_id for Firebase will be the email (string)
        try:
            data = firebase_db.get_user_by_id(user_id)
            if data:
                data['id'] = user_id
                return FirebaseUser(data)
        except Exception:
            return None
        return None
    else:
        try:
            return db.session.get(User, int(user_id))
        except Exception:
            return None

# ============ AUTHENTICATION ROUTES ============

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if USE_FIREBASE:
            existing = firebase_db.get_user_by_email(email)
            if existing:
                flash('Email already exists!', 'danger')
                return redirect(url_for('register'))
            hashed_password = generate_password_hash(password)
            user_data = {
                'name': name,
                'email': email,
                'password': hashed_password,
                'created_at': datetime.now(UTC).isoformat()
            }
            # use email as document id for simplicity
            firebase_db.create_user(email, user_data)
        else:
            if User.query.filter_by(email=email).first():
                flash('Email already exists!', 'danger')
                return redirect(url_for('register'))
            hashed_password = generate_password_hash(password)
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if USE_FIREBASE:
            u = firebase_db.get_user_by_email(email)
            if u and check_password_hash(u.get('password', ''), password):
                u['id'] = u.get('email')
                user = FirebaseUser(u)
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Invalid email or password!', 'danger')
        else:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Invalid email or password!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

# ============ MAIN ROUTES ============

@app.route('/')
def index():
    # load products from Firebase if enabled, otherwise from SQLite
    products = []
    if USE_FIREBASE:
        try:
            products = firebase_db.list_products()
        except Exception:
            products = []
    else:
        prods = Product.query.order_by(Product.created_at.desc()).all()
        for p in prods:
            products.append({
                'id': p.id,
                'name': p.name,
                'description': p.description,
                'price': p.price,
                'image_path': p.image_path,
                'category': getattr(p, 'category', None),
                'show_on_homepage': bool(getattr(p, 'show_on_homepage', False)),
                'created_at': p.created_at
            })
    return render_template('index.html', products=products)


@app.route('/products')
def products_page():
    # Load products from local DB (or Firebase if enabled) and group into categories
    products = []
    if USE_FIREBASE:
        try:
            products = firebase_db.list_products()
        except Exception:
            products = []
    else:
        prods = Product.query.order_by(Product.created_at.desc()).all()
        for p in prods:
            products.append({
                'id': p.id,
                'name': p.name,
                'description': p.description,
                'price': p.price,
                'image_path': p.image_path,
                'created_at': p.created_at
            })

    # categorize products by simple keyword matching on name/description
    categories = {
        'T-Shirts': [],
        'Mugs': [],
        'Keychains': [],
        'Cushions': [],
        'Corporate Gifts': [],
        'Others': []
    }

    def detect_category(item):
        text = ((item.get('name') or '') + ' ' + (item.get('description') or '')).lower()
        if any(k in text for k in ['t-shirt', 'tshirt', 't shirts', 'tshirts', 'shirt']):
            return 'T-Shirts'
        if 'mug' in text:
            return 'Mugs'
        if 'keychain' in text or 'key chain' in text:
            return 'Keychains'
        if 'cushion' in text or 'pillow' in text:
            return 'Cushions'
        if 'corporate' in text or 'gift' in text or 'gifting' in text:
            return 'Corporate Gifts'
        return 'Others'

    for item in products:
        # prefer explicit DB category when present
        cat = item.get('category') or detect_category(item)
        categories.setdefault(cat, []).append(item)

    return render_template('products.html', categories=categories)

@app.route('/download-catalog')
def download_catalog():
    try:
        return send_file('static/catalogue.pdf', as_attachment=True, download_name='Prabha_Graphics_Catalogue.pdf')
    except:
        flash('Catalog file not found!', 'danger')
        return redirect(url_for('index'))

@app.route('/customer-details', methods=['GET', 'POST'])
def customer_details():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        product_interest = request.form.get('product_interest')
        quantity = request.form.get('quantity')
        company = request.form.get('company')
        address = request.form.get('address')
        
        if USE_FIREBASE:
            customer = {
                'name': name,
                'email': email,
                'mobile': mobile,
                'product_interest': product_interest,
                'quantity': int(quantity) if quantity else None,
                'company': company,
                'address': address,
                'created_at': datetime.now(UTC).isoformat(),
                'status': 'new',
                'notes': None,
                'updated_at': datetime.now(UTC).isoformat()
            }
            firebase_db.add_customer(customer)
        else:
            customer = Customer(name=name, email=email, mobile=mobile, product_interest=product_interest, quantity=quantity, company=company, address=address)
            db.session.add(customer)
            db.session.commit()
        
        flash('Customer details submitted successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('customer_details.html')

@app.route('/get-quote', methods=['GET', 'POST'])
def get_quote():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        mobile = request.form.get('mobile')
        product = request.form.get('product_type')
        budget = request.form.get('budget')
        details = request.form.get('requirements')
        
        if USE_FIREBASE:
            quote_request = {
                'name': name,
                'email': email,
                'mobile': mobile,
                'product': product,
                'budget': budget,
                'details': details,
                'created_at': datetime.now(UTC).isoformat(),
                'status': 'pending',
                'notes': None,
                'updated_at': datetime.now(UTC).isoformat()
            }
            firebase_db.add_quote(quote_request)
        else:
            quote_request = QuoteRequest(name=name, email=email, mobile=mobile, product=product, budget=budget, details=details)
            db.session.add(quote_request)
            db.session.commit()
        
        flash('Quote request submitted successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('get_quote.html')

# ============ ADMIN ROUTES ============

# Admin credentials are stored in `instance/admin_settings.json` if present.
# Fall back to environment variables for initial default.
env_admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
env_admin_pwd = os.environ.get('ADMIN_PASSWORD', 'prabha123')
if not admin_settings.get_admin_username():
    # initialize settings file with env defaults if missing
    admin_settings.set_admin_credentials(env_admin_user, env_admin_pwd)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # verify against stored admin settings
        stored_user = admin_settings.get_admin_username()
        if username == stored_user and admin_settings.check_admin_password(password):
            # check if OTP is required
            if admin_settings.get_require_otp():
                # generate an OTP and require verification
                import random
                code = f"{random.randint(100000, 999999)}"
                admin_settings.set_otp(code)
                # In production you'd send SMS here. For now we log it.
                app.logger.info('Admin OTP for login: %s', code)
                # keep the username in session until verification
                session['pending_admin_username'] = username
                flash('OTP sent to admin mobile (for testing OTP is logged).', 'info')
                return redirect(url_for('admin_verify_otp'))
            session['admin_logged_in'] = True
            flash('Admin logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials!', 'danger')
    
    return render_template('admin_login.html')

@app.route('/admin')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('Please login to access admin panel', 'warning')
        return redirect(url_for('admin_login'))
    # Filter out specific previous flashes that are irrelevant to admin view
    # (e.g. 'Customer details submitted successfully!' or 'Quote request submitted successfully!')
    # while preserving other messages.
    from flask import get_flashed_messages
    prior = get_flashed_messages(with_categories=True)
    for cat, msg in prior:
        if not isinstance(msg, str):
            flash(msg, cat)
            continue
        low = msg.lower()
        if 'customer details submitted' in low or 'quote request submitted' in low or 'quote request submitted successfully' in low:
            # skip these user-submission notifications for admin view
            continue
        # re-flash allowed messages so they show on the admin page
        flash(msg, cat)
    
    # Load customers and quotes from the local Flask/SQLAlchemy DB
    customers = Customer.query.order_by(Customer.created_at.desc()).all()
    quotes = QuoteRequest.query.order_by(QuoteRequest.created_at.desc()).all()

    # Load products from local DB so admin sees newly added items
    products = []
    prods = Product.query.order_by(Product.created_at.desc()).all()
    for p in prods:
        products.append({
            'id': p.id,
            'name': p.name,
            'description': p.description,
            'price': p.price,
            'image_path': p.image_path,
            'category': getattr(p, 'category', None),
            'show_on_homepage': bool(getattr(p, 'show_on_homepage', False)),
            'created_at': p.created_at
        })
    
    return render_template('admin_dashboard.html', customers=customers, quotes=quotes, products=products)


@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings_view():
    if not session.get('admin_logged_in'):
        flash('Please login to access admin settings', 'warning')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        mobile = request.form.get('mobile')
        require_otp = bool(request.form.get('require_otp'))

        if username:
            # if password provided, update both, otherwise only username
            if password:
                admin_settings.set_admin_credentials(username, password)
            else:
                # update username keeping password same
                s = admin_settings.load_settings()
                s['username'] = username
                admin_settings.save_settings(s)

        if mobile is not None:
            admin_settings.set_mobile(mobile)

        admin_settings.set_require_otp(require_otp)
        flash('Settings updated successfully.', 'success')
        return redirect(url_for('admin_settings_view'))

    # GET
    username = admin_settings.get_admin_username()
    mobile = admin_settings.get_mobile()
    require_otp = admin_settings.get_require_otp()
    return render_template('admin_settings.html', username=username, mobile=mobile, require_otp=require_otp)


@app.route('/admin/settings/send-otp', methods=['POST'])
def admin_send_otp():
    # Send OTP to the configured mobile for admin (used for verifying mobile or login)
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': 'Not authenticated'}), 401
    mobile = admin_settings.get_mobile()
    if not mobile:
        return jsonify({'success': False, 'message': 'No mobile number configured'}), 400
    import random
    code = f"{random.randint(100000, 999999)}"
    admin_settings.set_otp(code)
    # In production you'd integrate an SMS provider here. For now we log the code.
    app.logger.info('OTP sent to %s: %s', mobile, code)
    return jsonify({'success': True, 'message': 'OTP sent (check server logs for code in this demo)'}), 200


@app.route('/admin/settings/verify-mobile', methods=['POST'])
def admin_verify_mobile():
    if not session.get('admin_logged_in'):
        flash('Please login to access admin settings', 'warning')
        return redirect(url_for('admin_login'))
    code = request.form.get('otp_code')
    if not code:
        flash('OTP code required', 'danger')
        return redirect(url_for('admin_settings'))
    if admin_settings.verify_otp(code):
        admin_settings.clear_otp()
        flash('Mobile number verified successfully.', 'success')
    else:
        flash('Invalid or expired OTP code.', 'danger')
    return redirect(url_for('admin_settings'))


@app.route('/admin/verify-otp', methods=['GET', 'POST'])
def admin_verify_otp():
    # used when login requires OTP
    if request.method == 'POST':
        code = request.form.get('otp_code')
        pending = session.get('pending_admin_username')
        if not pending:
            flash('No pending admin login found.', 'danger')
            return redirect(url_for('admin_login'))
        if admin_settings.verify_otp(code):
            admin_settings.clear_otp()
            session.pop('pending_admin_username', None)
            session['admin_logged_in'] = True
            flash('Admin logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid or expired OTP code.', 'danger')
            return redirect(url_for('admin_verify_otp'))
    return render_template('admin_verify_otp.html')

@app.route('/admin/customer/<customer_id>/update', methods=['POST'])
def update_customer(customer_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    if USE_FIREBASE:
        cust = firebase_db.get_customer(customer_id)
        if not cust:
            return redirect(url_for('admin_dashboard'))
        updates = {
            'status': request.form.get('status'),
            'notes': request.form.get('notes'),
            'updated_at': datetime.now(UTC).isoformat()
        }
        firebase_db.update_customer(customer_id, updates)
        flash(f"Customer {cust.get('name')} updated!", 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        customer = db.session.get(Customer, customer_id)
        if not customer:
            return redirect(url_for('admin_dashboard'))
        customer.status = request.form.get('status')
        customer.notes = request.form.get('notes')
        customer.updated_at = datetime.now(UTC)
        db.session.commit()
        flash(f'Customer {customer.name} updated!', 'success')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/quote/<quote_id>/update', methods=['POST'])
def update_quote(quote_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    if USE_FIREBASE:
        q = firebase_db.get_quote(quote_id)
        if not q:
            return redirect(url_for('admin_dashboard'))
        updates = {
            'status': request.form.get('status'),
            'notes': request.form.get('notes'),
            'updated_at': datetime.now(UTC).isoformat()
        }
        firebase_db.update_quote(quote_id, updates)
        flash(f"Quote from {q.get('name')} updated!", 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        quote = db.session.get(QuoteRequest, quote_id)
        if not quote:
            return redirect(url_for('admin_dashboard'))
        quote.status = request.form.get('status')
        quote.notes = request.form.get('notes')
        quote.updated_at = datetime.now(UTC)
        db.session.commit()
        flash(f'Quote from {quote.name} updated!', 'success')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out', 'info')
    return redirect(url_for('index'))

@app.route('/admin/customer/<customer_id>/delete', methods=['POST'])
def delete_customer(customer_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    if USE_FIREBASE:
        cust = firebase_db.get_customer(customer_id)
        if not cust:
            return redirect(url_for('admin_dashboard'))
        name = cust.get('name')
        firebase_db.delete_customer(customer_id)
        flash(f'Customer {name} has been deleted!', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        customer = db.session.get(Customer, customer_id)
        if not customer:
            return redirect(url_for('admin_dashboard'))
        name = customer.name
        db.session.delete(customer)
        db.session.commit()
        flash(f'Customer {name} has been deleted!', 'success')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/add', methods=['POST'])
def add_product():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    name = request.form.get('name')
    description = request.form.get('description')
    price = request.form.get('price')
    category = request.form.get('category')
    show_on_homepage = True if request.form.get('show_on_homepage') in ('on', 'true', '1') else False
    image = request.files.get('image')

    image_path = None
    if image and image.filename:
        from werkzeug.utils import secure_filename
        filename = secure_filename(image.filename)
        # If using Firebase, upload directly to Storage and get public URL
        if USE_FIREBASE:
            # destination path inside bucket
            dest_path = f'products/{filename}'
            try:
                # image.stream is a file-like object
                public_url = firebase_db.upload_fileobj_to_storage(image.stream, dest_path, content_type=image.mimetype)
                image_path = public_url
                # also store storage path for deletion
                data['image_storage_path'] = dest_path
            except Exception:
                # fallback to saving locally
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(save_path)
                image_path = save_path.replace('\\', '/')
        else:
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(save_path)
            image_path = save_path.replace('\\', '/')

    data = {
        'name': name,
        'description': description,
        'price': float(price) if price else None,
        'image_path': image_path,
        'category': category,
        'show_on_homepage': show_on_homepage,
        'created_at': datetime.now(UTC).isoformat()
    }

    if USE_FIREBASE:
        prod_id = firebase_db.add_product(data)
    else:
        # create product safely even if DB schema hasn't been migrated
        prod = Product(name=name, description=description, price=(float(price) if price else None), image_path=image_path)
        try:
            prod.category = category
            prod.show_on_homepage = show_on_homepage
        except Exception:
            # attribute may not exist on older DB schema
            pass
        db.session.add(prod)
        db.session.commit()
        prod_id = prod.id

    flash('Product added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    if USE_FIREBASE:
        p = firebase_db.get_product(product_id)
        if p:
            storage_path = p.get('image_storage_path') or p.get('image_path')
            if storage_path:
                try:
                    firebase_db.delete_blob(storage_path)
                except Exception:
                    pass
        firebase_db.delete_product(product_id)
    else:
        p = db.session.get(Product, int(product_id))
        if p:
            if p.image_path:
                try:
                    os.remove(p.image_path)
                except Exception:
                    pass
            db.session.delete(p)
            db.session.commit()
    flash('Product deleted', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/toggle-home', methods=['POST'])
def toggle_product_home(product_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    if USE_FIREBASE:
        # For Firebase path, update document
        p = firebase_db.get_product(product_id)
        if p:
            new = not bool(p.get('show_on_homepage'))
            firebase_db.update_product(product_id, {'show_on_homepage': new})
    else:
        try:
            p = db.session.get(Product, int(product_id))
        except Exception:
            p = None
        if p:
            try:
                p.show_on_homepage = not bool(p.show_on_homepage)
                db.session.commit()
            except Exception:
                db.session.rollback()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/quote/<quote_id>/delete', methods=['POST'])
def delete_quote(quote_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    if USE_FIREBASE:
        q = firebase_db.get_quote(quote_id)
        if not q:
            return redirect(url_for('admin_dashboard'))
        name = q.get('name')
        firebase_db.delete_quote(quote_id)
        flash(f'Quote from {name} has been deleted!', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        quote = db.session.get(QuoteRequest, quote_id)
        if not quote:
            return redirect(url_for('admin_dashboard'))
        name = quote.name
        db.session.delete(quote)
        db.session.commit()
        flash(f'Quote from {name} has been deleted!', 'success')
        return redirect(url_for('admin_dashboard'))

# ============ CHATBOT API - TREE MODEL ============

CHATBOT_TREE = {
    'start': {
        'message': 'Welcome to Prabha Graphics! How can I help you today?',
        'options': [
            {'text': 'I want to place a customer details request', 'next': 'customer_details'},
            {'text': 'I want to request a quote', 'next': 'quote_request'},
            {'text': 'I have questions about products', 'next': 'product_questions'},
            {'text': 'Talk to a representative', 'next': 'contact_support'}
        ]
    },
    'customer_details': {
        'message': 'Great! Please share your details. What is your full name?',
        'type': 'input',
        'next': 'customer_email'
    },
    'customer_email': {
        'message': 'Thank you! What is your email address?',
        'type': 'input',
        'next': 'customer_mobile'
    },
    'customer_mobile': {
        'message': 'What is your mobile number?',
        'type': 'input',
        'next': 'customer_company'
    },
    'customer_company': {
        'message': 'What is your company name? (optional)',
        'type': 'input',
        'next': 'customer_product'
    },
    'customer_product': {
        'message': 'Which product are you interested in?',
        'options': [
            {'text': 'T-Shirts', 'next': 'customer_quantity'},
            {'text': 'Mugs', 'next': 'customer_quantity'},
            {'text': 'Keychains', 'next': 'customer_quantity'},
            {'text': 'Cushions', 'next': 'customer_quantity'},
            {'text': 'Custom Items', 'next': 'customer_quantity'}
        ]
    },
    'customer_quantity': {
        'message': 'How many units do you need?',
        'type': 'input',
        'next': 'customer_color_pref'
    },
    'customer_color_pref': {
        'message': 'Do you have any color or design preferences?',
        'type': 'input',
        'next': 'customer_delivery_date'
    },
    'customer_delivery_date': {
        'message': 'When do you need the order delivered? (Please specify a date or time frame)',
        'type': 'input',
        'next': 'customer_address_followup'
    },
    'customer_address_followup': {
        'message': 'Please provide the delivery address (if different from company address, or type "same").',
        'type': 'input',
        'next': 'customer_file_upload'
    },
    'customer_file_upload': {
        'message': 'Do you have a logo or design file to share? (You can email it to prabhagraphics@gmail.com or mention "No" if not)',
        'type': 'input',
        'next': 'customer_confirmation'
    },
    'customer_confirmation': {
        'message': 'Perfect! Your details have been recorded. Our team will contact you soon!',
        'type': 'end'
    },
    'quote_request': {
        'message': 'Excellent! I\'ll help you get a quote. What is your name?',
        'type': 'input',
        'next': 'quote_email'
    },
    'quote_email': {
        'message': 'What is your email address?',
        'type': 'input',
        'next': 'quote_mobile'
    },
    'quote_mobile': {
        'message': 'What is your mobile number?',
        'type': 'input',
        'next': 'quote_product'
    },
    'quote_product': {
        'message': 'Which product do you need a quote for?',
        'options': [
            {'text': 'T-Shirts', 'next': 'quote_budget'},
            {'text': 'Mugs', 'next': 'quote_budget'},
            {'text': 'Keychains', 'next': 'quote_budget'},
            {'text': 'Cushions', 'next': 'quote_budget'},
            {'text': 'Custom Items', 'next': 'quote_budget'}
        ]
    },
    'quote_budget': {
        'message': 'What is your budget range?',
        'options': [
            {'text': 'Under ₹10,000', 'next': 'quote_color_pref'},
            {'text': '₹10,000 - ₹50,000', 'next': 'quote_color_pref'},
            {'text': '₹50,000 - ₹1,00,000', 'next': 'quote_color_pref'},
            {'text': '₹1,00,000 - ₹5,00,000', 'next': 'quote_color_pref'},
            {'text': 'Above ₹5,00,000', 'next': 'quote_color_pref'}
        ]
    },
    'quote_color_pref': {
        'message': 'Do you have any color, material, or design preferences for this quote?',
        'type': 'input',
        'next': 'quote_delivery_date'
    },
    'quote_delivery_date': {
        'message': 'What is your expected delivery date or timeline?',
        'type': 'input',
        'next': 'quote_address_followup'
    },
    'quote_address_followup': {
        'message': 'Where should the order be delivered? (Please provide address or type "same as company")',
        'type': 'input',
        'next': 'quote_file_upload'
    },
    'quote_file_upload': {
        'message': 'Do you have a logo, artwork, or reference file to share? (You can email it to prabhagraphics@gmail.com or mention "No" if not)',
        'type': 'input',
        'next': 'quote_details'
    },
    'quote_details': {
        'message': 'Can you share any specific details or requirements about your project?',
        'type': 'input',
        'next': 'quote_confirmation'
    },
    'quote_confirmation': {
        'message': 'Thank you! We\'ve received your quote request. Our team will send you a detailed quotation soon!',
        'type': 'end'
    },
    'product_questions': {
        'message': 'What would you like to know about our products?',
        'options': [
            {'text': 'Available products', 'next': 'products_list'},
            {'text': 'Pricing', 'next': 'pricing_info'},
            {'text': 'Customization options', 'next': 'customization_info'},
            {'text': 'Back to main menu', 'next': 'start'}
        ]
    },
    'products_list': {
        'message': 'We offer: T-Shirts, Mugs, Keychains, Cushions, Clocks, Caps, Bottles, and Custom Combo Packs. Download our catalog for more details!',
        'options': [
            {'text': 'Request a quote', 'next': 'quote_request'},
            {'text': 'Share my details', 'next': 'customer_details'},
            {'text': 'Back to main menu', 'next': 'start'}
        ]
    },
    'pricing_info': {
        'message': 'Pricing varies based on product type, quantity, and customization. Please request a quote to get accurate pricing for your specific needs!',
        'options': [
            {'text': 'Request a quote', 'next': 'quote_request'},
            {'text': 'Talk to support', 'next': 'contact_support'},
            {'text': 'Back to main menu', 'next': 'start'}
        ]
    },
    'customization_info': {
        'message': 'We offer full customization including printing, embroidery, and color options. Contact our team for specific requirements!',
        'options': [
            {'text': 'Contact support', 'next': 'contact_support'},
            {'text': 'Request a quote', 'next': 'quote_request'},
            {'text': 'Back to main menu', 'next': 'start'}
        ]
    },
    'contact_support': {
        'message': 'You can reach us at: 📞 074579 94888 or visit us at Shop No. 4/74, Adarsh Market, Gomti Nagar, Lucknow. Would you like to do anything else?',
        'options': [
            {'text': 'Request a quote', 'next': 'quote_request'},
            {'text': 'Share my details', 'next': 'customer_details'},
            {'text': 'Back to main menu', 'next': 'start'}
        ]
    }
}

@app.route('/api/chatbot', methods=['POST'])
def chatbot_api():
    data = request.get_json()
    current_node = data.get('node', 'start')
    user_input = data.get('input', '')
    
    if current_node not in CHATBOT_TREE:
        current_node = 'start'
    
    node_data = CHATBOT_TREE[current_node].copy()

    # If this node expects free-text input and we received input, advance to the next node
    if node_data.get('type') == 'input' and user_input:
        next_node = node_data.get('next')
        if next_node in CHATBOT_TREE:
            nxt = CHATBOT_TREE[next_node]
            return jsonify({
                'message': nxt['message'],
                'node': next_node,
                'options': nxt.get('options', []),
                'type': nxt.get('type', 'options')
            })

    # Handle next node based on user input (for options)
    if user_input and 'options' in node_data:
        for option in node_data['options']:
            if option['text'].lower() == user_input.lower():
                next_node = option['next']
                if next_node in CHATBOT_TREE:
                    nxt = CHATBOT_TREE[next_node]
                    return jsonify({
                        'message': nxt['message'],
                        'node': next_node,
                        'options': nxt.get('options', []),
                        'type': nxt.get('type', 'options')
                    })

    # Return current node data
    return jsonify({
        'message': node_data['message'],
        'node': current_node,
        'options': node_data.get('options', []),
        'type': node_data.get('type', 'options')
    })


# Simple route to serve the chatbot UI
@app.route('/chatbot', endpoint='chatbot_page')
def chatbot_page():
    return render_template('chatbot.html')

    # ============ CREATE DATABASE ============

if __name__ == '__main__':
    with app.app_context():
        if USE_FIREBASE:
            print('Running with Firebase backend (Firestore).')
        else:
            # Print the actual database file path being used
            engine = db.engine
            print('Database file path:', engine.url.database)
            db.create_all()
    app.run(debug=True)
