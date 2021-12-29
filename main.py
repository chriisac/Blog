import flask
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUserForm, UserLoginForm, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##login manager
login_manager = LoginManager(app)

gravatar = Gravatar(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.id == 1:
            return flask.abort(403)
        return f(*args, **kwargs)
    return decorated_function


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create foreign key, "users_id" the users refers to the table name of User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the user object, the "posts" object refers to the posts property in the User class
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    comments = relationship("Comment", back_populates="post_parent")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # Create a link to author in User db
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    # Create a link to post in BlogPost db
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post_parent = relationship("BlogPost", back_populates="comments")


#
# db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("get_all_posts"))

    form = RegisterUserForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered. Log in instead.")
            return redirect(url_for("login"))

        try:
            password = form.password.data
            hash_and_salted_password = generate_password_hash(password, "pbkdf2:sha256", 8)
            new_user = User(
                email=form.email.data,
                password=hash_and_salted_password,
                name=form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            print(e)
            return flask.abort(500)
        finally:
            login_user(new_user)
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = UserLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email not found.")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Wrong password.")
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(post_id=post_id)
    comment_form = CreateCommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                author=current_user,
                text=comment_form.comment.data,
                post_parent=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You need to log in, in order to comment.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, comment_form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
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



@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
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
    app.run(debug=True, host='0.0.0.0', port=5000)
