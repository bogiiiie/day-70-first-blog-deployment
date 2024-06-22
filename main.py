from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap5(app)

# Initialize SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define User model
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000), nullable=False)
    posts = db.relationship('BlogPost', back_populates='author', cascade='all, delete-orphan')
    comments = db.relationship('Comment', back_populates='author', cascade='all, delete-orphan')

# Define BlogPost model
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False, default=date.today().strftime("%B %d, %Y"))
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = db.relationship('User', back_populates='posts')
    comments = db.relationship('Comment', back_populates='post', cascade='all, delete-orphan')

# Define Comment model
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'), nullable=False)
    author = db.relationship('User', back_populates='comments')
    post = db.relationship('BlogPost', back_populates='comments')

# Admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:  # Adjust this condition based on your admin logic
            abort(403, description="You do not have permission to access this resource.")
        return f(*args, **kwargs)
    return decorated_function

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

# Login route
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            # flash('Invalid credentials. Please try again.', 'error')
            pass
    return render_template("login.html", form=form)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    # flash('You have been logged out.', 'success')
    return redirect(url_for('get_all_posts'))

# Home page route
@app.route('/')
def get_all_posts():
    try:
        all_posts = BlogPost.query.all()
        print(f"Number of posts retrieved: {len(all_posts)}")
        for post in all_posts:
            print(f"Post ID: {post.id}, Title: {post.title}")
        return render_template("index.html", all_posts=all_posts)
    except Exception as e:
        print(f"Error fetching posts: {str(e)}")
        return "Error fetching posts", 500

# Show post route
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    form = CommentForm()
    post_comments= post.comments
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.text.data,
            author=current_user,
            post=post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post.id, post_comments=post_comments))
    return render_template("post.html", post=post, form=form)

# Add new post route
@app.route("/new-post", methods=["GET", "POST"])
@login_required
# @admin_only- if you want the admin to just create a post
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html", form=form)

# Edit post route
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    form = CreatePostForm(obj=post)
    if form.validate_on_submit():
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.body = form.body.data
        post.img_url = form.img_url.data
        db.session.commit()
        return redirect(url_for('show_post', post_id=post.id))
    return render_template("make-post.html", form=form, is_edit=True)

# Delete post route
@app.route("/delete/<int:post_id>", methods=["POST"])
@login_required
@admin_only
def delete_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    # flash('Post deleted successfully.', 'success')
    return redirect(url_for('get_all_posts'))

# About page route
@app.route("/about")
def about():
    return render_template("about.html")

# Contact page route
@app.route("/contact")
def contact():
    return render_template("contact.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5092)
