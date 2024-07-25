from flask import Flask, request, session, render_template, redirect, url_for, flash, g
from flask_sqlalchemy import SQLAlchemy
from models import ChatMessage, db, User, Post, Like, Comment
from main import AIContentBot
import os
from dotenv import load_dotenv
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image
import cv2

load_dotenv()



app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application")

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    raise ValueError("No DATABASE_URI set for Flask application")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print(f"SQLALCHEMY_DATABASE_URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
db.init_app(app)

bot = AIContentBot()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_IMAGE_SIZE = (800, 800)
MAX_VIDEO_SIZE = (1280, 720)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def resize_image(file_path):
    with Image.open(file_path) as img:
        img.thumbnail(MAX_IMAGE_SIZE)
        img.save(file_path)

def resize_video(file_path):
    cap = cv2.VideoCapture(file_path)
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    
    if width > MAX_VIDEO_SIZE[0] or height > MAX_VIDEO_SIZE[1]:
        out = cv2.VideoWriter(file_path + '_temp.mp4', cv2.VideoWriter_fourcc(*'mp4v'), 30, MAX_VIDEO_SIZE)
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            resized_frame = cv2.resize(frame, MAX_VIDEO_SIZE)
            out.write(resized_frame)
        out.release()
        cap.release()
        os.replace(file_path + '_temp.mp4', file_path)

@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    return dict(current_user=g.user)

@app.route('/')
def index():
    if g.user is None:
        return redirect(url_for('login'))
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        bot.add_user_interests(username, [])
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in successfully', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content')
    file = request.files.get('media')
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        media_url = f'/static/uploads/{filename}'
        media_type = 'video' if filename.rsplit('.', 1)[1].lower() in ['mp4', 'mov'] else 'image'
        
        if media_type == 'image':
            resize_image(file_path)
        elif media_type == 'video':
            resize_video(file_path)
    else:
        media_url = None
        media_type = None

    print(f"Calling generate_and_check_content with: content={content}, user_id={g.user.id}, media_url={media_url}")
    result = bot.generate_and_check_content(content, g.user.id, media_url)
    print(f"Result from generate_and_check_content: {result}")

    if result is None:
        flash("An error occurred while processing your post. Please try again.", 'error')
        return redirect(url_for('index'))

    success, message = result
    if success:
        new_post = Post(content=message, user_id=g.user.id, media_url=media_url, media_type=media_type)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully', 'success')
    else:
        flash(message, 'error')
        if media_url:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    return redirect(url_for('index'))

@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    like = Like.query.filter_by(user_id=g.user.id, post_id=post_id).first()
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('Post unliked', 'success')
    else:
        new_like = Like(user_id=g.user.id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        flash('Post liked', 'success')
    return redirect(url_for('index'))

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def comment_post(post_id):
    content = request.form.get('content')
    print(f"Attempting to generate comment for post {post_id} with content: {content}")
    
    try:
        result = bot.generate_and_check_content(content, g.user.id)
        print(f"Result from generate_and_check_content: {result}")
        
        if result is None:
            raise ValueError("generate_and_check_content returned None")
        
        success, result = result
        
        if success:
            new_comment = Comment(content=result, user_id=g.user.id, post_id=post_id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added successfully', 'success')
        else:
            flash(result, 'error')
    except Exception as e:
        print(f"Error in comment_post: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'error')
    
    return redirect(url_for('index'))

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = user.posts.order_by(Post.timestamp.desc()).all()
    post_count = user.posts.count()
    return render_template('profile.html', user=user, posts=posts, post_count=post_count)

@app.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'error')
        return redirect(url_for('index'))
    if user.id == g.user.id:
        flash('You cannot follow yourself!', 'error')
        return redirect(url_for('profile', username=username))
    g.user.follow(user)
    db.session.commit()
    flash(f'You are now following {username}!', 'success')
    return redirect(url_for('profile', username=username))

@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'error')
        return redirect(url_for('index'))
    if user.id == g.user.id:
        flash('You cannot unfollow yourself!', 'error')
        return redirect(url_for('profile', username=username))
    g.user.unfollow(user)
    db.session.commit()
    flash(f'You have unfollowed {username}.', 'success')
    return redirect(url_for('profile', username=username))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != g.user.id:
        flash('You can only delete your own posts.', 'error')
        return redirect(url_for('index'))
    
    # Delete associated likes and comments
    Like.query.filter_by(post_id=post_id).delete()
    Comment.query.filter_by(post_id=post_id).delete()
    
    # Delete the post
    db.session.delete(post)
    db.session.commit()
    
    flash('Post deleted successfully', 'success')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


def create_tables():
    with app.app_context():
        db.create_all()

if __name__ == '__main__':
    create_tables()