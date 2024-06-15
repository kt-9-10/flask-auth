from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug import security


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()
        if user:
            flash("You've already signed up with that Email. Log in insisted.")
        else:
            hashed_password = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
            add_user = User(
                email=request.form.get('email'),
                name=request.form.get('name'),
                password=hashed_password,
            )
            with app.app_context():
                db.session.add(add_user)
                db.session.commit()

            user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()
            login_user(user)

            return redirect(url_for("secrets"))

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        user = db.session.execute(db.select(User).where(User.email == request.form.get("email"))).scalar()
        if user:
            if check_password_hash(user.password, request.form.get("password")):
                login_user(user)
                return redirect(url_for("secrets"))
            else:
                flash('Email or Password incorrect, Please try again.')

        else:
            flash('Email or Password incorrect, Please try again.')

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
