"""
Bell-LaPadula Security Model — Flask Backend
Run:  pip install flask flask-cors bcrypt
      python app.py
Open: http://localhost:5000
"""

import sqlite3, hashlib, hmac, os, json, secrets
from datetime import datetime
from functools import wraps

try:
    import bcrypt
    USE_BCRYPT = True
except ImportError:
    USE_BCRYPT = False

from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = 86400
CORS(app, supports_credentials=True)

DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'blp.db')

# ═══════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    schema_path = os.path.join(os.path.dirname(__file__), 'database', 'schema.sql')
    conn = get_db()
    with open(schema_path) as f:
        conn.executescript(f.read())

    # ── Seed users ──
    demo_users = [
        ('admin',    'admin123',   'Administrator', 4, 'admin', 'active'),
        ('manager',  'pass123',    'Manager',       4, 'user',  'active'),
        ('employee', 'secret456',  'Employee',      3, 'user',  'active'),
        ('intern',   'conf123',    'Intern',        2, 'user',  'active'),
        ('public',   'open789',    'Public User',   1, 'user',  'active'),
    ]
    for uname, pwd, dname, lvl, role, status in demo_users:
        if not conn.execute('SELECT 1 FROM users WHERE username=?', (uname,)).fetchone():
            conn.execute(
                'INSERT INTO users (username,password_hash,display_name,level,role,status) VALUES(?,?,?,?,?,?)',
                (uname, hash_password(pwd), dname, lvl, role, status)
            )
    conn.commit()

    # ── Seed files ──
    if not conn.execute('SELECT 1 FROM files').fetchone():
        mgr = conn.execute("SELECT id FROM users WHERE username='manager'").fetchone()['id']
        emp = conn.execute("SELECT id FROM users WHERE username='employee'").fetchone()['id']
        adm = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()['id']
        seed_files = [
            ('Operation Phoenix',   'doc', 4, mgr,
             'CLASSIFIED — Operation Phoenix Phase 3\nTarget: Infrastructure Upgrade\nTimeline: Q2 2025 · Budget: $4.2M\nStatus: In Progress\n\n[EYES ONLY — TOP SECRET]'),
            ('Project Aurora Specs','pdf', 4, mgr,
             'PROJECT AURORA — Technical Specifications\nModule A: Quantum Encryption\nModule B: Zero-Trust Networking\n\n[HIGHLY RESTRICTED]'),
            ('Q4 Revenue Report',   'xls', 3, emp,
             'Q4 Revenue Report\nTotal Revenue: $12.4M  Net Profit: $3.1M  Growth: +18%\n\n[SECRET — INTERNAL USE ONLY]'),
            ('Budget Forecast 2025','xls', 3, emp,
             'Budget Forecast 2025\nDept: Engineering  Allocation: $8.2M\n\n[SECRET — FINANCE]'),
            ('Employee Handbook',   'pdf', 2, adm,
             'Employee Handbook v3.2\nSection 1: Code of Conduct\nSection 2: Benefits\nSection 3: Security\n\n[CONFIDENTIAL]'),
            ('Company Newsletter',  'doc', 1, adm,
             'Monthly Newsletter — March 2025\nWelcome new team members!\nUpcoming: Annual picnic June 15\n\n[PUBLIC]'),
        ]
        for name, ftype, lvl, owner, content in seed_files:
            conn.execute(
                'INSERT INTO files(name,file_type,level,owner_id,content,images) VALUES(?,?,?,?,?,?)',
                (name, ftype, lvl, owner, content, '[]')
            )
        conn.commit()

    # ── Seed chat messages ──
    if not conn.execute('SELECT 1 FROM messages').fetchone():
        pairs = [
            ('admin',    'Welcome to Secure Chat. BLP rules filter visibility.',          4),
            ('manager',  'Secure channel operational. Level 4 messages visible to L4+.', 4),
            ('employee', 'Q4 report review scheduled for Monday.',                        3),
            ('intern',   'Thanks for the warm welcome!',                                  2),
        ]
        for uname, msg, lvl in pairs:
            uid = conn.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()['id']
            conn.execute('INSERT INTO messages(user_id,content,level) VALUES(?,?,?)', (uid, msg, lvl))
        conn.commit()
    conn.close()

# ═══════════════════════════════════════════
# PASSWORD HASHING
# ═══════════════════════════════════════════
def hash_password(password: str) -> str:
    if USE_BCRYPT:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"sha256:{salt}:{h}"

def verify_password(password: str, stored: str) -> bool:
    if USE_BCRYPT and not stored.startswith('sha256:'):
        try:
            return bcrypt.checkpw(password.encode(), stored.encode())
        except Exception:
            return False
    parts = stored.split(':')
    if len(parts) != 3:
        return False
    _, salt, h = parts
    return hmac.compare_digest(hashlib.sha256((salt + password).encode()).hexdigest(), h)

# ═══════════════════════════════════════════
# BLP ACCESS CONTROL
# ═══════════════════════════════════════════
def blp_read(user_level, obj_level):
    """Simple Security: No Read Up"""
    return user_level >= obj_level

def blp_write(user_level, target_level):
    """Star Property: No Write Down"""
    return user_level <= target_level

def blp_dm(sender_level, recipient_level):
    """DM BLP: sender level >= recipient level (no writing up)"""
    return sender_level >= recipient_level

# ═══════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        conn = get_db()
        u = conn.execute('SELECT role FROM users WHERE id=?', (session['user_id'],)).fetchone()
        conn.close()
        if not u or u['role'] != 'admin':
            return jsonify({'error': 'Admin required'}), 403
        return f(*args, **kwargs)
    return decorated

def current_user():
    conn = get_db()
    u = conn.execute(
        'SELECT id,username,display_name,level,role,status FROM users WHERE id=?',
        (session['user_id'],)
    ).fetchone()
    conn.close()
    return dict(u) if u else None

def log_audit(user_id, action, target, target_level, allowed, reason=''):
    conn = get_db()
    conn.execute(
        'INSERT INTO audit_log(user_id,action,target,target_level,allowed,reason,ip_address) VALUES(?,?,?,?,?,?,?)',
        (user_id, action, target, target_level, 1 if allowed else 0, reason, request.remote_addr)
    )
    conn.commit()
    conn.close()

def file_to_dict(row, owner_name=None):
    d = dict(row)
    try:
        d['images'] = json.loads(d.get('images') or '[]')
    except Exception:
        d['images'] = []
    if owner_name:
        d['owner'] = owner_name
    return d

# ═══════════════════════════════════════════
# ROUTES — MAIN
# ═══════════════════════════════════════════
@app.route('/')
def index():
    return render_template('index.html')

# ── AUTH ──────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    conn = get_db()
    u = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not u or not verify_password(password, u['password_hash']):
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401
    if u['status'] == 'pending':
        conn.close()
        return jsonify({'error': 'Account pending admin approval'}), 403
    if u['status'] == 'suspended':
        conn.close()
        return jsonify({'error': 'Account suspended'}), 403
    conn.execute('UPDATE users SET last_login=? WHERE id=?', (datetime.utcnow(), u['id']))
    conn.commit()
    conn.close()
    session.permanent = True
    session['user_id'] = u['id']
    log_audit(u['id'], 'LOGIN', 'System', u['level'], True, 'Login successful')
    return jsonify({'user': {'id':u['id'],'username':u['username'],'display_name':u['display_name'],'level':u['level'],'role':u['role']}})

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    log_audit(session['user_id'], 'LOGOUT', 'System', 1, True, '')
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = (data.get('username') or '').strip().lower()
    password = data.get('password') or ''
    display_name = (data.get('display_name') or username).strip()
    level = int(data.get('level', 1))
    if not username or not password:
        return jsonify({'error': 'All fields required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if level not in (1,2,3,4):
        return jsonify({'error': 'Invalid level'}), 400
    conn = get_db()
    if conn.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
        conn.close()
        return jsonify({'error': 'Username already taken'}), 409
    conn.execute(
        'INSERT INTO users(username,password_hash,display_name,level,role,status) VALUES(?,?,?,?,?,?)',
        (username, hash_password(password), display_name, level, 'user', 'pending')
    )
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ── FILES ─────────────────────────────────
@app.route('/api/files')
@login_required
def list_files():
    """Return only files the user can READ (BLP: No Read Up)."""
    u = current_user()
    conn = get_db()
    rows = conn.execute('''
        SELECT f.id, f.name, f.file_type, f.level, f.images,
               f.created_at, f.updated_at, u.display_name AS owner, u.id AS owner_id
        FROM files f JOIN users u ON f.owner_id = u.id
        WHERE f.level <= ?
        ORDER BY f.level DESC, f.created_at DESC
    ''', (u['level'],)).fetchall()
    conn.close()
    files = []
    for r in rows:
        d = file_to_dict(r)
        d['owner_id'] = r['owner_id']
        d['can_read'] = True   # only readable ones returned
        files.append(d)
    return jsonify({'files': files})

@app.route('/api/files/<int:fid>/read')
@login_required
def read_file(fid):
    u = current_user()
    conn = get_db()
    row = conn.execute(
        'SELECT f.*, u.display_name AS owner, u.id AS owner_id FROM files f JOIN users u ON f.owner_id=u.id WHERE f.id=?',
        (fid,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'File not found'}), 404
    if not blp_read(u['level'], row['level']):
        log_audit(u['id'],'READ',row['name'],row['level'],False,f"No Read Up: level {u['level']} < {row['level']}")
        return jsonify({'error':'Access denied — No Read Up violation','blp_rule':'no_read_up'}), 403
    log_audit(u['id'],'READ',row['name'],row['level'],True,'Access granted')
    return jsonify({'file': file_to_dict(row)})

@app.route('/api/files/create', methods=['POST'])
@login_required
def create_file():
    """Create a new file — saves content + images to SQLite."""
    u = current_user()
    data = request.get_json()
    name       = (data.get('name') or '').strip()
    content    = data.get('content') or ''
    file_type  = (data.get('file_type') or 'doc').strip()
    target_lvl = int(data.get('level', u['level']))
    images     = data.get('images') or []   # list of base64 strings

    if not name:
        return jsonify({'error': 'File name is required'}), 400
    if not blp_write(u['level'], target_lvl):
        log_audit(u['id'],'CREATE',name,target_lvl,False,f"No Write Down: clearance {u['level']} > target {target_lvl}")
        return jsonify({'error':f"BLP violation — No Write Down. Cannot create at Level {target_lvl} with clearance Level {u['level']}."}), 403

    images_json = json.dumps(images)
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO files(name,file_type,level,owner_id,content,images) VALUES(?,?,?,?,?,?)',
        (name, file_type, target_lvl, u['id'], content, images_json)
    )
    new_id = cur.lastrowid
    conn.commit()
    row = conn.execute(
        'SELECT f.*, u.display_name AS owner, u.id AS owner_id FROM files f JOIN users u ON f.owner_id=u.id WHERE f.id=?',
        (new_id,)
    ).fetchone()
    conn.close()
    log_audit(u['id'],'CREATE',name,target_lvl,True,'File created — saved to SQLite database')
    return jsonify({'ok': True, 'file': file_to_dict(row)})

@app.route('/api/files/<int:fid>', methods=['PUT'])
@login_required
def edit_file(fid):
    """Edit file content — BLP: no downgrade of classification."""
    u = current_user()
    conn = get_db()
    row = conn.execute('SELECT * FROM files WHERE id=?', (fid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
    if not blp_read(u['level'], row['level']):
        conn.close()
        log_audit(u['id'],'EDIT',row['name'],row['level'],False,'Cannot read file')
        return jsonify({'error': 'Cannot edit a file you cannot read'}), 403
    if row['owner_id'] != u['id'] and u['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Only the file owner can edit'}), 403

    data      = request.get_json()
    new_level = int(data.get('level', row['level']))
    if new_level < row['level']:
        conn.close()
        log_audit(u['id'],'EDIT',row['name'],row['level'],False,f"Cannot downgrade from {row['level']} to {new_level}")
        return jsonify({'error': f"BLP violation — cannot downgrade classification from {row['level']} to {new_level}"}), 403
    if not blp_write(u['level'], new_level):
        conn.close()
        return jsonify({'error': 'No Write Down violation on target level'}), 403

    images_json = json.dumps(data.get('images', json.loads(row['images'] or '[]')))
    conn.execute(
        'UPDATE files SET name=?,content=?,file_type=?,level=?,images=?,updated_at=? WHERE id=?',
        (data.get('name', row['name']), data.get('content', row['content']),
         data.get('file_type', row['file_type']), new_level,
         images_json, datetime.utcnow(), fid)
    )
    conn.commit()
    updated = conn.execute(
        'SELECT f.*, u.display_name AS owner, u.id AS owner_id FROM files f JOIN users u ON f.owner_id=u.id WHERE f.id=?',
        (fid,)
    ).fetchone()
    conn.close()
    log_audit(u['id'],'EDIT',data.get('name',row['name']),new_level,True,'File edited — saved to database')
    return jsonify({'ok': True, 'file': file_to_dict(updated)})

@app.route('/api/files/<int:fid>', methods=['DELETE'])
@login_required
def delete_file(fid):
    u = current_user()
    conn = get_db()
    row = conn.execute('SELECT * FROM files WHERE id=?', (fid,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    if not blp_read(u['level'], row['level']):
        conn.close()
        return jsonify({'error': 'Insufficient clearance to delete'}), 403
    if row['owner_id'] != u['id'] and u['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Not the file owner'}), 403
    conn.execute('DELETE FROM files WHERE id=?', (fid,))
    conn.commit()
    conn.close()
    log_audit(u['id'],'DELETE',row['name'],row['level'],True,'File deleted from database')
    return jsonify({'ok': True})

# ── CHAT ──────────────────────────────────
@app.route('/api/chat/sc')
@login_required
def sc_get():
    u = current_user()
    conn = get_db()
    rows = conn.execute('''
        SELECT m.id, m.content, m.level, m.created_at, u.display_name, u.username
        FROM messages m JOIN users u ON m.user_id=u.id
        WHERE m.level <= ? ORDER BY m.created_at ASC LIMIT 200
    ''', (u['level'],)).fetchall()
    conn.close()
    return jsonify({'messages': [dict(r) for r in rows]})

@app.route('/api/chat/sc', methods=['POST'])
@login_required
def sc_send():
    u = current_user()
    content = (request.get_json().get('content') or '').strip()
    if not content:
        return jsonify({'error': 'Empty message'}), 400
    conn = get_db()
    cur = conn.execute('INSERT INTO messages(user_id,content,level) VALUES(?,?,?)', (u['id'], content, u['level']))
    mid = cur.lastrowid
    row = conn.execute(
        'SELECT m.*,u.display_name,u.username FROM messages m JOIN users u ON m.user_id=u.id WHERE m.id=?', (mid,)
    ).fetchone()
    conn.commit()
    conn.close()
    log_audit(u['id'],'CHAT_SC','Secure Channel',u['level'],True,'Message sent')
    return jsonify({'ok': True, 'message': dict(row)})

# ── AUDIT ─────────────────────────────────
@app.route('/api/audit')
@login_required
def get_audit():
    u = current_user()
    conn = get_db()
    if u['role'] == 'admin':
        rows = conn.execute('''
            SELECT a.*, u.display_name, u.username
            FROM audit_log a LEFT JOIN users u ON a.user_id=u.id
            ORDER BY a.created_at DESC LIMIT 300
        ''').fetchall()
    else:
        rows = conn.execute('''
            SELECT a.*, u.display_name, u.username
            FROM audit_log a LEFT JOIN users u ON a.user_id=u.id
            WHERE a.user_id=? ORDER BY a.created_at DESC LIMIT 200
        ''', (u['id'],)).fetchall()
    conn.close()
    return jsonify({'logs': [dict(r) for r in rows]})

# ── ADMIN ─────────────────────────────────
@app.route('/api/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    rows = conn.execute(
        'SELECT id,username,display_name,level,role,status,created_at,last_login FROM users ORDER BY level DESC'
    ).fetchall()
    conn.close()
    return jsonify({'users': [dict(r) for r in rows]})

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    conn = get_db()
    stats = {
        'total_users':    conn.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'active_users':   conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        'pending_users':  conn.execute("SELECT COUNT(*) FROM users WHERE status='pending'").fetchone()[0],
        'total_files':    conn.execute('SELECT COUNT(*) FROM files').fetchone()[0],
        'audit_entries':  conn.execute('SELECT COUNT(*) FROM audit_log').fetchone()[0],
        'denied_accesses':conn.execute('SELECT COUNT(*) FROM audit_log WHERE allowed=0').fetchone()[0],
    }
    conn.close()
    return jsonify({'stats': stats})

@app.route('/api/admin/users/<int:uid>/approve', methods=['POST'])
@admin_required
def approve_user(uid):
    conn = get_db()
    u = conn.execute('SELECT username FROM users WHERE id=?', (uid,)).fetchone()
    conn.execute("UPDATE users SET status='active' WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    log_audit(session['user_id'],'ADMIN',f"Approved @{u['username'] if u else uid}",4,True,'')
    return jsonify({'ok': True})

@app.route('/api/admin/users/<int:uid>/suspend', methods=['POST'])
@admin_required
def suspend_user(uid):
    conn = get_db()
    u = conn.execute('SELECT username FROM users WHERE id=?', (uid,)).fetchone()
    conn.execute("UPDATE users SET status='suspended' WHERE id=?", (uid,))
    conn.commit()
    conn.close()
    log_audit(session['user_id'],'ADMIN',f"Suspended @{u['username'] if u else uid}",4,True,'')
    return jsonify({'ok': True})

@app.route('/api/admin/users/<int:uid>/delete', methods=['DELETE'])
@admin_required
def delete_user(uid):
    if uid == session['user_id']:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=?', (uid,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})

# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════
if __name__ == '__main__':
    init_db()
    print("\n" + "="*55)
    print("  Bell-LaPadula Security Model — Server Running")
    print("="*55)
    print("  URL      : http://localhost:5000")
    print("  Database : database/blp.db  (SQLite)")
    print(f"  Bcrypt   : {'YES ✓' if USE_BCRYPT else 'NO — using sha256 fallback'}")
    print("="*55)
    print("  Demo accounts:")
    print("    admin    / admin123   → Level 4, Admin role")
    print("    manager  / pass123    → Level 4, Top Secret")
    print("    employee / secret456  → Level 3, Secret")
    print("    intern   / conf123    → Level 2, Confidential")
    print("    public   / open789    → Level 1, Public")
    print("="*55 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
