from flask import Flask, request, jsonify, session, send_from_directory, redirect
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3, os, secrets, json, base64, time, hmac
from datetime import datetime

try:
    from pywebpush import webpush, WebPushException
except ImportError:
    webpush = None
    WebPushException = Exception

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    serialization = None
    ec = None

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'style_again.db')
IS_PROD = os.environ.get('FLASK_ENV', '').lower() == 'production' or os.environ.get('PRODUCTION', '').lower() == 'true'

app = Flask(__name__, static_folder=BASE, static_url_path='')
app.secret_key = os.environ.get('STYLE_AGAIN_SECRET') or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=IS_PROD,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,  # 2 MB JSON/image payload limit
)

ADMIN_ID = os.environ.get('STYLE_AGAIN_ADMIN_ID', 'admin')
ADMIN_PASSWORD_HASH = os.environ.get('STYLE_AGAIN_ADMIN_PASSWORD_HASH', '').strip()
ADMIN_PASSWORD_PLAIN = os.environ.get('STYLE_AGAIN_ADMIN_PASSWORD', '').strip()
if IS_PROD and (not ADMIN_PASSWORD_HASH or not os.environ.get('STYLE_AGAIN_SECRET')):
    raise RuntimeError('Production startup requires STYLE_AGAIN_SECRET and STYLE_AGAIN_ADMIN_PASSWORD_HASH.')
if not ADMIN_PASSWORD_HASH and ADMIN_PASSWORD_PLAIN:
    ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD_PLAIN)
if not ADMIN_PASSWORD_HASH:
    # Local development only: generate a random password instead of shipping a known default.
    ADMIN_PASSWORD_PLAIN = secrets.token_urlsafe(18)
    ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD_PLAIN)
    print('\n[STYLE AGAIN] Local admin credentials generated for this run:')
    print(f'  Admin ID: {ADMIN_ID}')
    print(f'  Password: {ADMIN_PASSWORD_PLAIN}')
    print('Set STYLE_AGAIN_ADMIN_PASSWORD_HASH before publishing.\n')

# Simple in-process login throttle. For multi-server deployments, use Redis or another shared limiter.
LOGIN_BUCKET = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 15 * 60
LOCKOUT_SECONDS = 15 * 60


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()
    c.execute('''CREATE TABLE IF NOT EXISTS orders(
      id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT UNIQUE, name TEXT, phone TEXT,
      email TEXT, address TEXT, pin TEXT, items TEXT, size TEXT, total REAL, status TEXT DEFAULT 'Payment screenshot pending',
      created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS push_subscriptions(
      id INTEGER PRIMARY KEY CHECK (id=1), subscription TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS products(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL,
      price REAL NOT NULL, old_price REAL DEFAULT 0, stock INTEGER DEFAULT 0, sizes TEXT DEFAULT '[]',
      condition TEXT DEFAULT '9/10', description TEXT DEFAULT '', image TEXT DEFAULT '', created_at TEXT)''')
    if c.execute('SELECT COUNT(*) FROM products').fetchone()[0] == 0:
        defaults = [
          ('Washed Oversized Tee','T-Shirts',699,999,2,['S','M','L','XL'],'9/10'),
          ('Archive Graphic Tee','T-Shirts',799,1199,1,['M','L'],'8/10'),
          ('Heavyweight Boxy Hoodie','Hoodies',1299,1799,3,['M','L','XL'],'9/10'),
          ('Vintage Varsity Jacket','Jackets',1899,2499,1,['L'],'9/10'),
          ('Utility Cargo Pants','Pants',1099,1499,4,['30','32','34'],'9/10'),
          ('Faded Denim Jacket','Jackets',1599,2199,1,['M','L'],'8/10'),
          ('Relaxed Street Pants','Pants',999,1399,2,['30','32','34'],'9/10'),
          ('Minimal Logo Hoodie','Hoodies',1399,1899,2,['M','L','XL'],'10/10')
        ]
        for x in defaults:
            c.execute('INSERT INTO products(name,category,price,old_price,stock,sizes,condition,description,image,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
              (*x[:5], json.dumps(x[5]), x[6], 'Curated thrift piece. Condition checked before dispatch.', '', datetime.now().isoformat(timespec='seconds')))
    c.commit(); c.close()


def is_same_origin():
    origin = request.headers.get('Origin')
    if origin:
        return origin.rstrip('/') == request.host_url.rstrip('/')
    referer = request.headers.get('Referer')
    if referer:
        return referer.startswith(request.host_url)
    # Browsers generally omit both for same-origin form/API requests in some configurations.
    return True


def csrf_ok():
    return is_same_origin()


def admin_required():
    return bool(session.get('admin') is True)


def login_key():
    return request.remote_addr or 'unknown'


def login_allowed():
    now = time.time()
    key = login_key()
    bucket = LOGIN_BUCKET.get(key)
    if not bucket or now - bucket['first'] > LOGIN_WINDOW:
        LOGIN_BUCKET[key] = {'first': now, 'attempts': 0, 'locked_until': 0}
        return True
    return now >= bucket.get('locked_until', 0)


def record_failed_login():
    key = login_key(); now = time.time()
    bucket = LOGIN_BUCKET.setdefault(key, {'first': now, 'attempts': 0, 'locked_until': 0})
    if now - bucket['first'] > LOGIN_WINDOW:
        bucket.update(first=now, attempts=0, locked_until=0)
    bucket['attempts'] += 1
    if bucket['attempts'] >= MAX_LOGIN_ATTEMPTS:
        bucket['locked_until'] = now + LOCKOUT_SECONDS


def clear_failed_logins():
    LOGIN_BUCKET.pop(login_key(), None)


@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Cache-Control'] = response.headers.get('Cache-Control', 'no-store' if request.path.startswith('/api/admin') else 'public, max-age=300')
    if IS_PROD:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.route('/')
def home():
    return send_from_directory(BASE, 'index.html')


@app.route('/admin')
def admin_login_page():
    return send_from_directory(BASE, 'admin.html')


@app.route('/admin-dashboard.html')
def admin_dashboard_page():
    if not admin_required():
        return redirect('/admin')
    return send_from_directory(BASE, 'admin-dashboard.html')


def vapid_paths():
    return os.path.join(BASE, 'vapid_private.pem'), os.path.join(BASE, 'vapid_public.txt')


def ensure_vapid_keys():
    if serialization is None or ec is None:
        return None, None
    private_path, public_path = vapid_paths()
    if os.path.exists(private_path) and os.path.exists(public_path):
        return open(private_path, 'rb').read(), open(public_path, 'r', encoding='utf-8').read().strip()
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public_bytes = private_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    public_b64 = base64.urlsafe_b64encode(public_bytes).rstrip(b'=').decode('ascii')
    open(private_path, 'wb').write(private_bytes)
    open(public_path, 'w', encoding='utf-8').write(public_b64)
    return private_bytes, public_b64


def send_push(payload):
    if webpush is None:
        print('Push notifications disabled: install pywebpush.')
        return
    private_key, public_key = ensure_vapid_keys()
    if not private_key:
        return
    c = db(); row = c.execute('SELECT subscription FROM push_subscriptions WHERE id=1').fetchone(); c.close()
    if not row:
        return
    try:
        webpush(json.loads(row['subscription']), json.dumps(payload), vapid_private_key=private_key,
                vapid_claims={'sub': os.environ.get('STYLE_AGAIN_VAPID_EMAIL', 'mailto:admin@styleagain.local')})
    except WebPushException as e:
        status = getattr(getattr(e, 'response', None), 'status_code', None)
        if status in (404, 410):
            c = db(); c.execute('DELETE FROM push_subscriptions WHERE id=1'); c.commit(); c.close()
        print('Push notification error:', e)
    except Exception as e:
        print('Push notification error:', e)


@app.get('/api/push/public-key')
def push_public_key():
    _, public_key = ensure_vapid_keys()
    return jsonify(public_key=public_key)


@app.post('/api/admin/push/subscribe')
def push_subscribe():
    if not admin_required() or not csrf_ok():
        return jsonify(error='Unauthorized'), 401
    data = request.get_json(silent=True) or {}
    if not data.get('endpoint') or not data.get('keys'):
        return jsonify(ok=False, error='Invalid subscription'), 400
    c = db(); c.execute('INSERT INTO push_subscriptions(id,subscription) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET subscription=excluded.subscription', (json.dumps(data),)); c.commit(); c.close()
    return jsonify(ok=True)


@app.post('/api/orders')
def create_order():
    data = request.get_json(silent=True) or {}
    required = ['order_id','name','phone','address','pin','items','size','total']
    if not all(data.get(k) for k in required):
        return jsonify(ok=False, error='Missing order details'), 400
    try:
        total = float(data['total'])
        if total < 0 or total > 10000000:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify(ok=False, error='Invalid total'), 400
    c = db()
    try:
        c.execute('INSERT INTO orders(order_id,name,phone,email,address,pin,items,size,total,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
          (str(data['order_id'])[:80], str(data['name'])[:120], str(data['phone'])[:30], str(data.get('email',''))[:160],
           str(data['address'])[:500], str(data['pin'])[:20], str(data['items'])[:5000], str(data['size'])[:200], total,
           datetime.now().isoformat(timespec='seconds')))
        c.commit()
    except sqlite3.IntegrityError:
        c.close(); return jsonify(ok=False, error='Order ID already exists'), 409
    c.close()
    send_push({'title':'STYLE AGAIN — NEW ORDER','body':f"Order {data['order_id']} from {data['name']} • ₹{total:g}",'order_id':data['order_id'],'url':'/admin-dashboard.html'})
    return jsonify(ok=True)


@app.get('/api/products')
def products_list():
    c = db(); rows = c.execute('SELECT * FROM products ORDER BY id DESC').fetchall(); c.close()
    out = []
    for r in rows:
        x = dict(r); x['sizes'] = json.loads(x['sizes'] or '[]'); out.append(x)
    return jsonify(products=out)


def valid_product_payload(d):
    if not d.get('name') or not d.get('category'):
        return False, 'Name and category required'
    try:
        price = float(d.get('price', 0)); old = float(d.get('old_price', 0)); stock = int(d.get('stock', 0))
        if price < 0 or old < 0 or stock < 0 or stock > 100000: raise ValueError
    except (TypeError, ValueError):
        return False, 'Invalid price or stock'
    sizes = d.get('sizes', [])
    if not isinstance(sizes, list) or len(sizes) > 30:
        return False, 'Invalid sizes'
    image = d.get('image', '') or ''
    if image and (len(image) > 1_500_000 or not image.startswith('data:image/')):
        return False, 'Invalid or oversized image'
    return True, None


@app.post('/api/admin/products')
def product_create():
    if not admin_required() or not csrf_ok(): return jsonify(error='Unauthorized'), 401
    d = request.get_json(silent=True) or {}; ok, err = valid_product_payload(d)
    if not ok: return jsonify(error=err), 400
    c = db(); cur = c.execute('INSERT INTO products(name,category,price,old_price,stock,sizes,condition,description,image,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',
      (str(d['name'])[:160], str(d['category'])[:80], float(d.get('price',0)), float(d.get('old_price',0)), int(d.get('stock',0)),
       json.dumps(d.get('sizes',[])), str(d.get('condition','9/10'))[:30], str(d.get('description',''))[:2000], d.get('image',''), datetime.now().isoformat(timespec='seconds')))
    c.commit(); pid = cur.lastrowid; c.close(); return jsonify(ok=True, id=pid)


@app.put('/api/admin/products/<int:pid>')
def product_update(pid):
    if not admin_required() or not csrf_ok(): return jsonify(error='Unauthorized'), 401
    d = request.get_json(silent=True) or {}; ok, err = valid_product_payload(d)
    if not ok: return jsonify(error=err), 400
    c = db(); c.execute('UPDATE products SET name=?,category=?,price=?,old_price=?,stock=?,sizes=?,condition=?,description=?,image=? WHERE id=?',
      (str(d['name'])[:160], str(d['category'])[:80], float(d.get('price',0)), float(d.get('old_price',0)), int(d.get('stock',0)),
       json.dumps(d.get('sizes',[])), str(d.get('condition','9/10'))[:30], str(d.get('description',''))[:2000], d.get('image',''), pid)); c.commit(); c.close(); return jsonify(ok=True)


@app.delete('/api/admin/products/<int:pid>')
def product_delete(pid):
    if not admin_required() or not csrf_ok(): return jsonify(error='Unauthorized'), 401
    c = db(); c.execute('DELETE FROM products WHERE id=?', (pid,)); c.commit(); c.close(); return jsonify(ok=True)


@app.get('/api/orders')
def my_orders():
    phone = request.args.get('phone','').strip()
    if not phone: return jsonify(orders=[])
    c = db(); rows = c.execute('SELECT * FROM orders WHERE phone=? ORDER BY id DESC', (phone,)).fetchall(); c.close()
    return jsonify(orders=[dict(r) for r in rows])


@app.post('/api/admin/login')
def admin_login():
    if not login_allowed():
        return jsonify(ok=False, error='Too many attempts. Try again later.'), 429
    data = request.get_json(silent=True) or {}
    supplied_id = str(data.get('id',''))
    supplied_password = str(data.get('password',''))
    if hmac.compare_digest(supplied_id, ADMIN_ID) and check_password_hash(ADMIN_PASSWORD_HASH, supplied_password):
        clear_failed_logins()
        session.clear()
        session['admin'] = True
        session['admin_login_at'] = int(time.time())
        return jsonify(ok=True)
    record_failed_login()
    time.sleep(0.25)
    return jsonify(ok=False), 401


@app.post('/api/admin/logout')
def admin_logout():
    if not csrf_ok(): return jsonify(error='Unauthorized'), 401
    session.clear(); return jsonify(ok=True)


@app.get('/api/admin/orders')
def admin_orders():
    if not admin_required(): return jsonify(error='Unauthorized'), 401
    c = db(); rows = c.execute('SELECT * FROM orders ORDER BY id DESC').fetchall(); c.close()
    return jsonify(orders=[dict(r) for r in rows])


@app.post('/api/admin/order/<order_id>/status')
def admin_status(order_id):
    if not admin_required() or not csrf_ok(): return jsonify(error='Unauthorized'), 401
    data = request.get_json(silent=True) or {}
    status = data.get('status','Payment screenshot pending')
    allowed = {'Payment screenshot pending','Confirmed','Packed','Shipped','Delivered','Cancelled'}
    if status not in allowed: return jsonify(error='Invalid status'), 400
    c = db(); c.execute('UPDATE orders SET status=? WHERE order_id=?', (status, order_id)); c.commit(); c.close(); return jsonify(ok=True)


@app.route('/<path:path>')
def assets(path):
    # Never expose server-side secrets/databases/configuration as static files.
    blocked = {'style_again.db','vapid_private.pem','vapid_public.txt','.env','requirements.txt','app.py'}
    if os.path.basename(path) in blocked or path.startswith('__pycache__/'):
        return jsonify(error='Not found'), 404
    return send_from_directory(BASE, path)


if __name__ == '__main__':
    init(); ensure_vapid_keys()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
