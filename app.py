from flask import Flask, request, session, render_template, redirect, url_for, flash, g, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image
import cv2
import os
from dotenv import load_dotenv
from content_generation.generator import ContentGenerator
from content_generation.user_interests import UserInterestsManager
from content_moderation.moderator import ContentModerator
from bias_detection.bias_detector import BiasDetector
from feedback_loop.feedback_handler import FeedbackHandler
from user_auth.auth import UserAuth

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
db = SQLAlchemy(app)
# Model definitions
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    profile_picture = db.Column(db.String(255), default='default_profile.jpg')
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0
    

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media_url = db.Column(db.String(255))
    media_type = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    likes = db.relationship('Like', backref='post', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', cascade='all, delete-orphan')
    

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy='dynamic'))
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='notifications')
    actor = db.relationship('User', foreign_keys=[actor_id])
    post = db.relationship('Post', backref='notifications')

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

# AIContentBot class
class AIContentBot:
    def __init__(self):
        self.generator = ContentGenerator()
        self.moderator = ContentModerator()
        self.bias_detector = BiasDetector()
        self.feedback_handler = FeedbackHandler()
        self.user_interests = UserInterestsManager()
        self.user_auth = UserAuth()

    def generate_and_check_content(self, user_input, user_id, media_url=None):
        user_interests = self.user_interests.get_user_interests(user_id)
        prompt = f"Based on the following user input and interests, generate a social media post:\nUser Input: {user_input}\nUser Interests: {', '.join(user_interests)}"
        generated_content = self.generator.generate_content(prompt, user_interests)
        
        if media_url:
            generated_content += f" [Media: {media_url}]"
        
        is_appropriate, moderation_result = self.moderator.moderate_content(generated_content)
        if not is_appropriate:
            return False, f"Generated content violates community guidelines: {moderation_result}"
        
        bias_detected, bias_result = self.bias_detector.detect_bias(generated_content)
        if bias_detected:
            return False, f"Generated content contains bias: {bias_result}"
        
        return True, generated_content

    def login(self, username, password):
        return self.user_auth.login(username, password)

    def generate_response(self, comment, user_id):
        user_interests = self.user_interests.get_user_interests(user_id)
        response = self.generator.generate_response(comment, user_interests)
        return self.generate_and_check_content(response, user_id)

    def handle_user_interaction(self, content, user_reaction):
        self.feedback_handler.add_feedback(content, user_reaction)
        if len(self.feedback_handler.feedback_data) % 100 == 0:
            analysis = self.feedback_handler.analyze_feedback()
            print("Feedback Analysis:", analysis)
            self.feedback_handler.update_model()

    def add_user_interests(self, user_id, interests):
        self.user_interests.add_user_interests(user_id, interests)

    def get_user_interests(self, user_id):
        return self.user_interests.get_user_interests(user_id)

    def remove_user_interest(self, user_id, interest):
        self.user_interests.remove_user_interest(user_id, interest)

# Flask routes and functions
bot = AIContentBot()

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_IMAGE_SIZE = (800, 800)
MAX_VIDEO_SIZE = (1280, 720)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    
    media_url = None
    media_type = None
    
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

    print(f"Calling generate_and_check_content with: content={content}, user_id={g.user.id}")
    result = bot.generate_and_check_content(content, g.user.id)
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
    post = Post.query.get_or_404(post_id)
    if like:
        db.session.delete(like)
        db.session.commit()
        flash('Post unliked', 'success')
    else:
        new_like = Like(user_id=g.user.id, post_id=post_id)
        db.session.add(new_like)
        if post.user_id != g.user.id:
            notification = Notification(user_id=post.user_id, actor_id=g.user.id, type='like', post_id=post_id)
            db.session.add(notification)
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
            post = Post.query.get_or_404(post_id)
            if post.user_id != g.user.id:
                notification = Notification(user_id=post.user_id, actor_id=g.user.id, type='comment', post_id=post_id)
                db.session.add(notification)
            db.session.commit()
            flash('Comment added successfully', 'success')
        else:
            flash(result, 'error')
    except Exception as e:
        print(f"Error in comment_post: {str(e)}")
        flash(f"An error occurred: {str(e)}", 'error')
    return redirect(url_for('index')) 
    
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        bio = request.form.get('bio')
        file = request.files.get('profile_picture')

        if username and username != g.user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists', 'error')
            else:
                g.user.username = username

        g.user.bio = bio

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            g.user.profile_picture = filename

        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile', username=g.user.username))

    return render_template('edit_profile.html', user=g.user)

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
    if user == g.user:
        flash('You cannot follow yourself!', 'error')
        return redirect(url_for('profile', username=username))
    g.user.follow(user)
    notification = Notification(user_id=user.id, actor_id=g.user.id, type='follow')
    db.session.add(notification)
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
    if user == g.user:
        flash('You cannot unfollow yourself!', 'error')
        return redirect(url_for('profile', username=username))
    g.user.unfollow(user)
    db.session.commit()
    flash(f'You have unfollowed {username}.', 'success')
    return redirect(url_for('profile', username=username))

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=g.user.id).order_by(Notification.timestamp.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/delete_notification/<int:notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != g.user.id:
        flash('You can only delete your own notifications.', 'error')
        return redirect(url_for('notifications'))
    
    db.session.delete(notification)
    db.session.commit()
    
    flash('Notification deleted successfully', 'success')
    return redirect(url_for('notifications'))

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
