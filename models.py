from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()

bcrypt = Bcrypt()


def connect_db(app):
    """Connect to database."""

    db.app = app
    db.init_app(app)


class User(db.Model):
    __tablename__ = "users"

    username = db.Column(db.String(20), unique=True,
                         primary_key=True)
    password = db.Column(db.String, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)

    @classmethod
    def register(cls, username, password, email, first_name, last_name):
        """Register user with hashed password and return user."""
        # hash the password
        hashed_pwd = bcrypt.generate_password_hash(password)
        # turn the hashed password into a regular string
        hashed_pwd_utf8 = hashed_pwd.decode('utf8')

        return cls(username=username, password=hashed_pwd_utf8, email=email, first_name=first_name, last_name=last_name)

    @classmethod
    def authenticate(cls, username, password):
        """
        Validate the users exists and the password is correct.

        Return user if valid and false if else
        """
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            return user
        else:
            return False


class Feedback(db.Model):
    __tablename__ = "feedback"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String, nullable=False)
    username = db.Column(db.String, db.ForeignKey("users.username"))

    user = db.relationship('User', backref="feedback")
