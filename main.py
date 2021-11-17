from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Table
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base

def admin_only(f): # f is edit_post func
    @wraps(f)
    def decorated_func(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_func

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['CKEDITOR_PKG_TYPE'] = 'basic'
ckeditor = CKEditor(app)
# ckeditor.init_app(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# LOGIN BY FLASK-LOGIN
login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    name = Column(String(250), nullable=False)
    password = Column(String(100))
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = 'comments'
    id = Column(Integer, primary_key=True)
    text = Column(Text, nullable=False)
    comment_author = relationship("User", back_populates="comments")
    comment_author_id = Column(Integer, ForeignKey("users.id"))
    post = relationship("BlogPost", back_populates="comments")
    post_id = Column(Integer, ForeignKey("blog_posts.id"))

# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register(): # email 1@po.lo / pwd 1 / name n1
    form = RegisterForm() # form is a wtf.quick_form
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Your email is already registered. Log in from the login page')
            return redirect(url_for('login'))
        hashed_pwd = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hashed_pwd
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        logged_user = User.query.filter_by(email=email).first()
        if logged_user:
            if check_password_hash(logged_user.password, password): # verifica pwd criptata
                login_user(logged_user)
                return redirect(url_for('get_all_posts')) # allora return della pagina
            else:
                flash('The password is incorrect. Please try again')
                return redirect(url_for('login'))
        else:
            flash('The email address is not registerd. Please check for the email you inserted')
            return redirect(url_for('login'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id): # user name c1, email c1@po.lo, pwd c1
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Only logged-in users can write comments')
            return redirect(url_for('login'))
        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author_id=current_user.id,
            post_id=requested_post.id
        )
        db.session.add(new_comment)
        db.session.commit()
        # comments = Comment.query.filter_by(post_id=requested_post.id)
        return render_template('post.html', post=requested_post, form=comment_form)
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
