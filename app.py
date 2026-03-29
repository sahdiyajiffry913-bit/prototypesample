import os
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("UILINGO_SECRET_KEY", "dev-change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "mysql+pymysql://root:@127.0.0.1:3306/prototypedb",
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

ADMIN_SIGNUP_SECRET = "123"
ROLES = frozenset({"student", "lecturer", "admin"})


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    # DB column is "password" (stores werkzeug hash); Python name stays password_hash
    password_hash = db.Column("password", db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    is_blocked = db.Column(db.Boolean, nullable=False, default=False)

    def set_password(self, raw: str) -> None:
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        user = db.session.get(User, session["user_id"])
        if user is None or user.is_blocked:
            session.clear()
            flash("Your account is disabled or no longer exists. Please contact an admin.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*allowed_roles: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "warning")
                return redirect(url_for("login"))
            role = session.get("role")
            if role not in allowed_roles:
                flash("You do not have access to that page.", "error")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)

        return wrapped

    return decorator


def dashboard_url_for_role(role: str) -> str:
    if role == "student":
        return url_for("student_dashboard")
    if role == "lecturer":
        return url_for("lecturer_dashboard")
    if role == "admin":
        return url_for("admin_dashboard")
    return url_for("login")


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        flash("Username and password are required.", "error")
        return render_template("login.html"), 200

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 200

    if user.is_blocked:
        flash("This account has been blocked. Contact an administrator.", "error")
        return render_template("login.html"), 200

    session.clear()
    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role

    flash(f"Welcome back, {user.username}.", "success")
    return redirect(dashboard_url_for_role(user.role))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "").strip().lower()
    admin_code = (request.form.get("admin_code") or "").strip()

    if not username or not password:
        flash("Username and password are required.", "error")
        return render_template("register.html"), 200

    if role not in ROLES:
        flash("Please choose a valid role.", "error")
        return render_template("register.html"), 200

    if role == "admin" and admin_code != ADMIN_SIGNUP_SECRET:
        flash("Invalid admin verification code.", "error")
        return render_template("register.html"), 200

    if User.query.filter_by(username=username).first():
        flash("That username is already taken.", "error")
        return render_template("register.html"), 200

    user = User(username=username, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    flash("Account created. You can log in now.", "success")
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return redirect(dashboard_url_for_role(session["role"]))


@app.route("/student/dashboard")
@login_required
@role_required("student")
def student_dashboard():
    return render_template(
        "dashboard_student.html",
        username=session.get("username"),
    )


@app.route("/lecturer/dashboard")
@login_required
@role_required("lecturer")
def lecturer_dashboard():
    return render_template(
        "dashboard_lecturer.html",
        username=session.get("username"),
    )


@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    return render_template(
        "dashboard_admin.html",
        username=session.get("username"),
    )


@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    users = User.query.order_by(User.id).all()
    return render_template(
        "admin_users.html",
        username=session.get("username"),
        users=users,
        me_id=session["user_id"],
    )


@app.route("/admin/users/<int:user_id>/block", methods=["POST"])
@login_required
@role_required("admin")
def admin_block_user(user_id):
    if user_id == session["user_id"]:
        flash("You cannot block your own account.", "error")
        return redirect(url_for("admin_users"))
    target = db.session.get(User, user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))
    target.is_blocked = True
    db.session.commit()
    flash(f"User “{target.username}” is now blocked and cannot log in.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/unblock", methods=["POST"])
@login_required
@role_required("admin")
def admin_unblock_user(user_id):
    target = db.session.get(User, user_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin_users"))
    target.is_blocked = False
    db.session.commit()
    flash(f"User “{target.username}” can log in again.", "success")
    return redirect(url_for("admin_users"))


@app.cli.command("init-db")
def init_db():
    """Create database tables (run once: flask --app app init-db)."""
    db.create_all()
    print("Tables ensured (create_all).")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
