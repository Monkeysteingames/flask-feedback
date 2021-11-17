from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import LoginForm, RegisterForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///flask_feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "Bustywusty"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)


@app.route('/')
def redirect_to_register():
    """Redict to register page"""
    return redirect('/register')


@app.route('/users/<username>')
def show_user_profile(username):
    """Show the user profile for the logged in user"""
    if "user_username" not in session:
        flash("Please login first.", 'danger')
        return redirect('/login')
    user = User.query.get_or_404(username)
    all_feedback = Feedback.query.all()
    return render_template('user.html', user=user, feedback=all_feedback)


@app.route('/users/<username>/delete', methods=["POST"])
def delete_user(username):
    """Delete user from database and return to login page"""
    if session['user_username'] != username:
        flash("Please login to this account first.", 'danger')
        return redirect('/login')
    user = User.query.get_or_404(username)
    db.session.delete(user)
    db.session.commit()
    session.pop('user_username')
    flash("User deleted!", "success")
    return redirect('/login')


@app.route('/users/<username>/feedback/add', methods=["GET", "POST"])
def add_feedback(username):
    """"Handle form to create/post feedback"""
    if session['user_username'] != username:
        flash("Please login to this account first.", 'danger')
        return redirect('/login')
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        new_fb = Feedback(title=title, content=content, username=username)
        db.session.add(new_fb)
        db.session.commit()
        flash("Feedback created!", 'info')
        return redirect(f"/users/{username}")
    return render_template("feedback_add.html", form=form)


@app.route('/feedback/<int:fb_id>/update', methods=["GET", "POST"])
def edit_feedback(fb_id):
    """"Handle form to update feedback"""
    fb = Feedback.query.get_or_404(fb_id)
    if session['user_username'] != fb.username:
        flash("Please login to this account first.", 'danger')
        return redirect('/login')
    form = FeedbackForm()
    if form.validate_on_submit():
        fb.title = form.title.data
        fb.content = form.content.data
        db.session.commit()
        flash("Feedback updated!", 'info')
        return redirect(f"/users/{fb.username}")
    return render_template("feedback_edit.html", form=form)


@app.route('/feedback/<int:fb_id>/delete', methods=["POST"])
def delete_feedback(fb_id):
    """Remove the feedback from the database"""
    if 'user_username' not in session:
        flash("Please login first.", 'danger')
        return redirect('login')
    fb = Feedback.query.get_or_404(fb_id)
    if fb.username == session["user_username"]:
        db.session.delete(fb)
        db.session.commit()
        flash("Feedback deleted!", "primary")
        return redirect(f"/users/{fb.username}")
    flash("You don't have permission to do that!", 'danger')
    return redirect(f"/users/{fb.username}")


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Show a form that will allow the user to create an account(user)"""
    form = RegisterForm()
    if form.validate_on_submit():
        # gather form data nand generate new user from it
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = User.register(username=username, password=password,
                                 email=email, first_name=first_name, last_name=last_name)

        db.session.add(new_user)
        # error handling, check is username has already been taken
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append(
                'Username already taken. Please choose another.')
            return render_template('register.html', form=form)

        session['user_username'] = new_user.username
        flash('Welcome!', 'success')
        return redirect(f"/users/{new_user.username}")

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username=username, password=password)
        if user:
            flash(f"Welcome back, {user.username}", 'primary')
            session['user_username'] = user.username
            return redirect(f"/users/{user.username}")
        else:
            form.username.errors = ["Invalid username/password."]

    return render_template('login.html', form=form)


@app.route('/logout')
def logout_user():
    session.pop('user_username')
    flash("Goodbye!", 'primary')
    return redirect('/')
