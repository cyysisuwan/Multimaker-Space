from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from database import init_db, get_db_connection
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Media configuration
UPLOAD_FOLDER = 'static/media'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize database
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stem-q')
def stem_q():
    return render_template('stem_q.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        
        conn = get_db_connection()
        try:
            hashed_password = generate_password_hash(password)
            conn.execute(
                'INSERT INTO users (username, email, password, full_name, role) VALUES (?, ?, ?, ?, ?)',
                (username, email, hashed_password, full_name, 'student')  # Default role is student
            )
            conn.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists')
        finally:
            conn.close()
    
    return render_template('login.html')

@app.route('/dashboard')
def student_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get class schedule
    classes = conn.execute(
        'SELECT * FROM class_schedule ORDER BY day, time'
    ).fetchall()
    
    # Get ONLY the current student's achievements
    achievements = conn.execute(
        'SELECT * FROM student_achievements WHERE user_id = ? ORDER BY date_achieved DESC',
        (session['user_id'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         classes=classes, 
                         achievements=achievements,
                         user=session)

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get users
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    
    # Get classes
    classes = conn.execute('SELECT * FROM class_schedule ORDER BY day, time').fetchall()
    
    # Get ALL achievements with user info
    achievements = conn.execute('''
        SELECT sa.*, u.username, u.full_name 
        FROM student_achievements sa 
        JOIN users u ON sa.user_id = u.id 
        ORDER BY sa.date_achieved DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin_dashboard.html', 
                         users=users, 
                         classes=classes, 
                         achievements=achievements)

@app.route('/contact')
def contact():
    return render_template('contact.html')

# MEDIA ROUTES - ADD THESE TO FIX THE ERROR
@app.route('/media')
def media_gallery():
    category = request.args.get('category', 'all')
    
    conn = get_db_connection()
    
    if category == 'all':
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            WHERE mg.is_active = 1 
            ORDER BY mg.uploaded_at DESC
        ''').fetchall()
    else:
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            WHERE mg.category = ? AND mg.is_active = 1 
            ORDER BY mg.uploaded_at DESC
        ''', (category,)).fetchall()
    
    # Get distinct categories for filter
    categories = conn.execute('''
        SELECT DISTINCT category FROM media_gallery WHERE is_active = 1 ORDER BY category
    ''').fetchall()
    
    conn.close()
    
    return render_template('media.html', 
                         media=media, 
                         categories=categories, 
                         current_category=category)

@app.route('/admin/media')
def admin_media():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    category = request.args.get('category', 'all')
    conn = get_db_connection()
    
    if category == 'all':
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            ORDER BY mg.uploaded_at DESC
        ''').fetchall()
    else:
        media = conn.execute('''
            SELECT mg.*, u.username 
            FROM media_gallery mg 
            JOIN users u ON mg.uploaded_by = u.id 
            WHERE mg.category = ? 
            ORDER BY mg.uploaded_at DESC
        ''', (category,)).fetchall()
    
    categories = conn.execute('SELECT DISTINCT category FROM media_gallery ORDER BY category').fetchall()
    conn.close()
    
    return render_template('admin_media.html', 
                         media=media, 
                         categories=categories, 
                         current_category=category)

@app.route('/admin/upload-media', methods=['POST'])
def upload_media():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('admin_media'))
    
    file = request.files['file']
    title = request.form.get('title', '')
    description = request.form.get('description', '')
    category = request.form.get('category', 'general')
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('admin_media'))
    
    if file and allowed_file(file.filename):
        # Check file size
        file.seek(0, os.SEEK_END)
        file_length = file.tell()
        file.seek(0)
        
        if file_length > MAX_FILE_SIZE:
            flash('File size too large. Maximum 16MB allowed.')
            return redirect(url_for('admin_media'))
        
        # Secure filename and make unique
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        timestamp = str(int(datetime.now().timestamp()))
        unique_filename = f"{base}_{timestamp}{ext}"
        
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        
        # Save to database
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO media_gallery (filename, title, description, category, uploaded_by) VALUES (?, ?, ?, ?, ?)',
            (unique_filename, title, description, category, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        flash('Media uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Allowed: PNG, JPG, JPEG, GIF, WEBP')
    
    return redirect(url_for('admin_media'))

@app.route('/admin/delete-media/<int:media_id>', methods=['POST'])
def delete_media(media_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get filename before deleting
    media = conn.execute('SELECT filename FROM media_gallery WHERE id = ?', (media_id,)).fetchone()
    
    if media:
        # Delete file from filesystem
        file_path = os.path.join(UPLOAD_FOLDER, media['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete from database
        conn.execute('DELETE FROM media_gallery WHERE id = ?', (media_id,))
        conn.commit()
        flash('Media deleted successfully!', 'success')
    else:
        flash('Media not found', 'error')
    
    conn.close()
    return redirect(url_for('admin_media'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Student achievement route (for students to add their own - if needed)
@app.route('/add_achievement', methods=['POST'])
def add_achievement():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    achievement = request.form['achievement']
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO student_achievements (user_id, achievement, date_achieved) VALUES (?, ?, DATE("now"))',
        (session['user_id'], achievement)
    )
    conn.commit()
    conn.close()
    
    flash('Achievement added successfully!')
    return redirect(url_for('student_dashboard'))

# Admin achievement management routes
@app.route('/add_achievement_admin', methods=['POST'])
def add_achievement_admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    try:
        user_id = request.form['user_id']
        achievement = request.form['achievement']
        date_achieved = request.form['date_achieved']
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO student_achievements (user_id, achievement, date_achieved) VALUES (?, ?, ?)',
            (user_id, achievement, date_achieved)
        )
        conn.commit()
        conn.close()
        
        flash('Achievement added successfully!')
    except Exception as e:
        flash(f'Error adding achievement: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_achievement/<int:achievement_id>', methods=['POST'])
def delete_achievement(achievement_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM student_achievements WHERE id = ?', (achievement_id,))
        conn.commit()
        conn.close()
        flash('Achievement deleted successfully!')
    except Exception as e:
        flash(f'Error deleting achievement: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

# Class management routes
@app.route('/add_class', methods=['POST'])
def add_class():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    try:
        class_name = request.form['class_name']
        day = request.form['day']
        time = request.form['time']
        instructor = request.form['instructor']
        duration = request.form['duration']
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO class_schedule (class_name, day, time, instructor, duration) VALUES (?, ?, ?, ?, ?)',
            (class_name, day, time, instructor, duration)
        )
        conn.commit()
        conn.close()
        flash('Class added successfully!')
    except Exception as e:
        flash(f'Error adding class: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_class/<int:class_id>', methods=['POST'])
def delete_class(class_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM class_schedule WHERE id = ?', (class_id,))
        conn.commit()
        conn.close()
        flash('Class deleted successfully!')
    except Exception as e:
        flash(f'Error deleting class: {str(e)}')
    
    return redirect(url_for('admin_dashboard'))

# User Management Routes
@app.route('/admin/add-user', methods=['POST'])
def add_user():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    username = request.form['username']
    full_name = request.form['full_name']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    
    conn = get_db_connection()
    
    # Check if username or email already exists
    existing_user = conn.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?', 
        (username, email)
    ).fetchone()
    
    if existing_user:
        flash('Username or email already exists.', 'error')
        conn.close()
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Create new user
        hashed_password = generate_password_hash(password)
        conn.execute(
            'INSERT INTO users (username, full_name, email, password, role) VALUES (?, ?, ?, ?, ?)',
            (username, full_name, email, hashed_password, role)
        )
        conn.commit()
        flash('User created successfully!', 'success')
    except Exception as e:
        flash(f'Error creating user: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Unauthorized access')
        return redirect(url_for('login'))
    
    # Prevent self-deletion
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    conn = get_db_connection()
    
    try:
        # Delete user's achievements first
        conn.execute('DELETE FROM student_achievements WHERE user_id = ?', (user_id,))
        
        # Delete user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('admin_dashboard'))

# Debug routes
@app.route('/test-data')
def test_data():
    """Test if data exists in database"""
    conn = get_db_connection()
    
    users_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    classes_count = conn.execute('SELECT COUNT(*) FROM class_schedule').fetchone()[0]
    achievements_count = conn.execute('SELECT COUNT(*) FROM student_achievements').fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'users_count': users_count,
        'classes_count': classes_count,
        'achievements_count': achievements_count,
        'database_file': 'multimaker.db'
    })

@app.route('/test-admin')
def test_admin():
    """Test if admin user exists"""
    conn = get_db_connection()
    admin = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    conn.close()
    
    if admin:
        return jsonify({
            'admin_exists': True,
            'admin_data': dict(admin)
        })
    else:
        return jsonify({'admin_exists': False})

if __name__ == '__main__':
    app.run(debug=True)