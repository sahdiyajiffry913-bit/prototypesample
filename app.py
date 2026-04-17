import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, send_from_directory, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("UILINGO_SECRET_KEY", "dev-change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "mysql+pymysql://root:@127.0.0.1:3306/prototypedb",
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max upload

db = SQLAlchemy(app)

ALLOWED_ACTIVITY_EXT = {"pdf"}


def utc_now():
    return datetime.now(timezone.utc)


def ensure_upload_dirs():
    act_root = os.path.join(app.config["UPLOAD_FOLDER"], "activities")
    os.makedirs(act_root, exist_ok=True)


def allowed_activity_filename(filename):
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_ACTIVITY_EXT


def rule_based_correct_english(text: str) -> str:
    """
    Very small "AI-like" rule-based English correction for prototypes.
    No database writes, no history storage.
    """
    if text is None:
        return ""

    s = str(text).replace("\u2019", "'")
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return s

    # Common typos
    s = re.sub(r"\bteh\b", "the", s, flags=re.I)
    s = re.sub(r"\brecieve\b", "receive", s, flags=re.I)

    # Capitalize first letter (first alphabetic char)
    m = re.search(r"[A-Za-z]", s)
    if m:
        idx = m.start()
        if s[idx].islower():
            s = s[:idx] + s[idx].upper() + s[idx + 1 :]

    # Fix standalone "i" -> "I"
    s = re.sub(r"(^|[\s])i(?=[\s,.!?])", r"\1I", s, flags=re.I)

    # Contractions
    s = re.sub(r"\bdont\b", "don't", s, flags=re.I)
    s = re.sub(r"\bcant\b", "can't", s, flags=re.I)
    s = re.sub(r"\bwont\b", "won't", s, flags=re.I)
    s = re.sub(r"\bdidnt\b", "didn't", s, flags=re.I)
    s = re.sub(r"\bdoesnt\b", "doesn't", s, flags=re.I)
    s = re.sub(r"\bisnt\b", "isn't", s, flags=re.I)
    s = re.sub(r"\barent\b", "aren't", s, flags=re.I)
    s = re.sub(r"\bwasnt\b", "wasn't", s, flags=re.I)
    s = re.sub(r"\bim\b", "I'm", s, flags=re.I)

    # Fix a/an based on first letter after the article (prototype rule)
    def fix_a_an(match: re.Match) -> str:
        a_or_an = match.group(1).lower()
        first_letter = match.group(2)
        is_vowel = first_letter.lower() in "aeiou"
        correct_article = "an" if is_vowel else "a"
        return f"{correct_article} {first_letter}"

    s = re.sub(r"\b(a|an)\s+([A-Za-z])", fix_a_an, s, flags=re.I)

    # Common grammar mistakes
    s = re.sub(r"\bI has\b", "I have", s, flags=re.I)
    s = re.sub(r"\byou was\b", "you were", s, flags=re.I)
    s = re.sub(r"\bthey was\b", "they were", s, flags=re.I)

    # End punctuation: add ? for question words, otherwise add a period
    if s and s[-1] not in ".!?":
        lower = s.lower()
        if re.match(r"^(what|where|when|why|how)\b", lower):
            s = s + "?"
        else:
            s = s + "."

    return s


# Free translation: MyMemory public API (en → ta / si). No API key; rate limits apply.
MYMEMORY_TRANSLATE_URL = "https://api.mymemory.translated.net/get"
TRANSLATE_MAX_CHARS = 500


def translate_english_to_target(text: str, target_lang: str):
    """
    Returns (translated_text, error_message). error_message is None on success.
    target_lang: 'ta' (Tamil) or 'si' (Sinhala).
    """
    if target_lang not in ("ta", "si"):
        return None, "Invalid target language."
    t = (text or "").strip()
    if not t:
        return None, "Text is required."
    if len(t) > TRANSLATE_MAX_CHARS:
        t = t[:TRANSLATE_MAX_CHARS]

    params = urllib.parse.urlencode({"q": t, "langpair": f"en|{target_lang}"})
    url = f"{MYMEMORY_TRANSLATE_URL}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "uilingo/1.0 (Flask student app)"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        return None, f"Translation service unavailable: {exc}"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "Invalid response from translation service."

    status = payload.get("responseStatus")
    if status not in (200, "200"):
        err = payload.get("responseDetails") or "Translation failed."
        return None, str(err)

    data = payload.get("responseData") or {}
    translated = (data.get("translatedText") or "").strip()
    if not translated:
        return None, "No translation returned."
    return translated, None


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


class ActivityUpload(db.Model):
    __tablename__ = "activity_upload"

    id = db.Column(db.Integer, primary_key=True)
    lecturer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


class GradeEntry(db.Model):
    __tablename__ = "grade_entry"
    __table_args__ = (
        db.UniqueConstraint(
            "lecturer_id",
            "student_id",
            "assignment_name",
            name="uq_grade_lecturer_student_assignment",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    lecturer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    assignment_name = db.Column(db.String(200), nullable=False)
    score = db.Column(db.Float, nullable=False)
    max_score = db.Column(db.Float, nullable=False, default=100.0)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


class GlossaryEntry(db.Model):
    __tablename__ = "glossary_entry"
    __table_args__ = (
        db.UniqueConstraint("lecturer_id", "term", name="uq_glossary_lecturer_term"),
    )

    id = db.Column(db.Integer, primary_key=True)
    lecturer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    term = db.Column(db.String(255), nullable=False)
    definition = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


class StudentMessage(db.Model):
    __tablename__ = "student_message"

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    message_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


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


@app.route("/student/resources")
@login_required
@role_required("student")
def student_resources():
    student_id = session["user_id"]

    activities = (
        ActivityUpload.query.order_by(ActivityUpload.created_at.desc()).all()
    )
    grades = (
        GradeEntry.query.filter_by(student_id=student_id)
        .order_by(GradeEntry.created_at.desc())
        .all()
    )
    glossary_terms = GlossaryEntry.query.order_by(GlossaryEntry.term.asc()).all()
    lecturers = User.query.filter_by(role="lecturer").all()
    lecturers_by_id = {u.id: u for u in lecturers}

    return render_template(
        "student_resources.html",
        username=session.get("username"),
        activities=activities,
        grades=grades,
        glossary_terms=glossary_terms,
        lecturers_by_id=lecturers_by_id,
    )


@app.route("/student/chat")
@login_required
@role_required("student")
def student_chat():
    me_id = session["user_id"]
    students = User.query.filter_by(role="student").order_by(User.username).all()
    students_by_id = {u.id: u for u in students}

    to_id = request.args.get("to_id", type=int)
    peer = None
    messages = []

    if to_id:
        peer = db.session.get(User, to_id)
        if not peer or peer.role != "student" or peer.id == me_id:
            flash("Pick a valid student to chat with.", "error")
            return redirect(url_for("student_chat"))

        messages = (
            StudentMessage.query.filter(
                (
                    (StudentMessage.sender_id == me_id)
                    & (StudentMessage.recipient_id == to_id)
                )
                | (
                    (StudentMessage.sender_id == to_id)
                    & (StudentMessage.recipient_id == me_id)
                )
            )
            .order_by(StudentMessage.created_at.desc())
            .limit(20)
            .all()
        )
        messages = list(reversed(messages))

    return render_template(
        "student_chat.html",
        username=session.get("username"),
        students=students,
        students_by_id=students_by_id,
        peer=peer,
        messages=messages,
        me_id=me_id,
        selected_to_id=to_id,
    )


@app.route("/student/chat/send", methods=["POST"])
@login_required
@role_required("student")
def student_chat_send():
    me_id = session["user_id"]
    to_id = request.form.get("to_id", type=int)
    message = (request.form.get("message") or "").strip()

    if not to_id or not message:
        flash("Pick a student and type your message.", "error")
        return redirect(url_for("student_chat"))

    if len(message) > 2000:
        flash("Message is too long (max 2000 characters).", "error")
        return redirect(url_for("student_chat", to_id=to_id))

    peer = db.session.get(User, to_id)
    if not peer or peer.role != "student" or peer.id == me_id:
        flash("Pick a valid student to chat with.", "error")
        return redirect(url_for("student_chat"))

    row = StudentMessage(
        sender_id=me_id,
        recipient_id=to_id,
        message_text=message,
    )
    db.session.add(row)
    db.session.commit()

    flash("Message sent.", "success")
    return redirect(url_for("student_chat", to_id=to_id))


@app.route("/lecturer/dashboard")
@login_required
@role_required("lecturer")
def lecturer_dashboard():
    return render_template(
        "dashboard_lecturer.html",
        username=session.get("username"),
    )


@app.route("/lecturer/activities", methods=["GET", "POST"])
@login_required
@role_required("lecturer")
def lecturer_activities():
    lecturer_id = session["user_id"]
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        upload = request.files.get("file")
        if not title:
            flash("Please enter a title for this activity.", "error")
            return redirect(url_for("lecturer_activities"))
        if not upload or not upload.filename:
            flash("Please choose a PDF file to upload.", "error")
            return redirect(url_for("lecturer_activities"))
        if not allowed_activity_filename(upload.filename):
            flash("Only PDF files are allowed for activities.", "error")
            return redirect(url_for("lecturer_activities"))

        ensure_upload_dirs()
        safe = secure_filename(upload.filename)
        if not safe:
            flash("Invalid file name.", "error")
            return redirect(url_for("lecturer_activities"))
        stored = f"{uuid.uuid4().hex}_{safe}"
        dest_dir = os.path.join(app.config["UPLOAD_FOLDER"], "activities", str(lecturer_id))
        os.makedirs(dest_dir, exist_ok=True)
        dest_path = os.path.join(dest_dir, stored)
        upload.save(dest_path)

        row = ActivityUpload(
            lecturer_id=lecturer_id,
            title=title,
            stored_filename=stored,
            original_filename=upload.filename,
        )
        db.session.add(row)
        db.session.commit()
        flash("Activity PDF uploaded.", "success")
        return redirect(url_for("lecturer_activities"))

    activities = (
        ActivityUpload.query.filter_by(lecturer_id=lecturer_id)
        .order_by(ActivityUpload.created_at.desc())
        .all()
    )
    return render_template(
        "lecturer_activities.html",
        username=session.get("username"),
        activities=activities,
    )


@app.route("/lecturer/activities/<int:activity_id>/download")
@login_required
@role_required("lecturer")
def lecturer_activity_download(activity_id):
    row = db.session.get(ActivityUpload, activity_id)
    lecturer_id = session["user_id"]
    if not row or row.lecturer_id != lecturer_id:
        flash("File not found.", "error")
        return redirect(url_for("lecturer_activities"))
    folder = os.path.join(app.config["UPLOAD_FOLDER"], "activities", str(lecturer_id))
    return send_from_directory(
        folder,
        row.stored_filename,
        as_attachment=True,
        download_name=row.original_filename,
    )


@app.route("/student/activities/<int:activity_id>/download")
@login_required
@role_required("student")
def student_activity_download(activity_id):
    row = db.session.get(ActivityUpload, activity_id)
    if not row:
        flash("File not found.", "error")
        return redirect(url_for("student_resources"))

    folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "activities",
        str(row.lecturer_id),
    )
    return send_from_directory(
        folder,
        row.stored_filename,
        as_attachment=True,
        download_name=row.original_filename,
    )


@app.route("/student/assistant/correct", methods=["POST"])
@login_required
@role_required("student")
def student_assistant_correct():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        message = (request.form.get("message") or "").strip()

    if not message:
        return {"error": "Message is required."}, 400

    corrected = rule_based_correct_english(message)
    return {
        "original": message,
        "corrected": corrected,
    }


@app.route("/student/translate", methods=["POST"])
@login_required
@role_required("student")
def student_translate():
    """Proxy to MyMemory: English → Tamil or Sinhala. No DB storage."""
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    target = (data.get("target") or "ta").strip().lower()
    if not text:
        text = (request.form.get("text") or "").strip()
    if not text:
        return {"error": "Text is required."}, 400
    if target not in ("ta", "si"):
        target = "ta"

    translated, err = translate_english_to_target(text, target)
    if err:
        return {"error": err}, 400
    return {"translated": translated, "target": target}


@app.route("/lecturer/grades", methods=["GET", "POST"])
@login_required
@role_required("lecturer")
def lecturer_grades():
    lecturer_id = session["user_id"]
    students = User.query.filter_by(role="student").order_by(User.username).all()

    if request.method == "POST":
        try:
            student_id = int(request.form.get("student_id") or "0")
        except ValueError:
            student_id = 0
        assignment = (request.form.get("assignment") or "").strip()
        score_raw = (request.form.get("score") or "").strip()
        max_raw = (request.form.get("max_score") or "").strip()

        if not student_id or not assignment:
            flash("Choose a student and enter an assignment name.", "error")
            return redirect(url_for("lecturer_grades"))
        try:
            score = float(score_raw)
        except ValueError:
            flash("Score must be a number.", "error")
            return redirect(url_for("lecturer_grades"))
        max_score = 100.0
        if max_raw != "":
            try:
                max_score = float(max_raw)
            except ValueError:
                flash("Max score must be a number.", "error")
                return redirect(url_for("lecturer_grades"))

        stu = db.session.get(User, student_id)
        if not stu or stu.role != "student":
            flash("That student is not valid.", "error")
            return redirect(url_for("lecturer_grades"))

        existing = GradeEntry.query.filter_by(
            lecturer_id=lecturer_id,
            student_id=stu.id,
            assignment_name=assignment,
        ).first()
        if existing:
            existing.score = score
            existing.max_score = max_score
            existing.created_at = utc_now()
            flash("Grade updated.", "success")
        else:
            db.session.add(
                GradeEntry(
                    lecturer_id=lecturer_id,
                    student_id=stu.id,
                    assignment_name=assignment,
                    score=score,
                    max_score=max_score,
                )
            )
            flash("Grade saved.", "success")
        db.session.commit()
        return redirect(url_for("lecturer_grades"))

    grades = (
        GradeEntry.query.filter_by(lecturer_id=lecturer_id)
        .order_by(GradeEntry.created_at.desc())
        .all()
    )
    students_by_id = {u.id: u for u in students}
    return render_template(
        "lecturer_grades.html",
        username=session.get("username"),
        grades=grades,
        students_by_id=students_by_id,
        students=students,
    )


@app.route("/lecturer/glossary")
@login_required
@role_required("lecturer")
def lecturer_glossary():
    lecturer_id = session["user_id"]
    terms = (
        GlossaryEntry.query.filter_by(lecturer_id=lecturer_id)
        .order_by(GlossaryEntry.term.asc())
        .all()
    )
    return render_template(
        "lecturer_glossary.html",
        username=session.get("username"),
        terms=terms,
    )


@app.route("/lecturer/glossary/add", methods=["POST"])
@login_required
@role_required("lecturer")
def lecturer_glossary_add():
    """Only handles term + definition from the glossary form (no file upload)."""
    lecturer_id = session["user_id"]
    term = (request.form.get("term") or "").strip()
    definition = (request.form.get("definition") or "").strip()
    if not term or not definition:
        flash("Enter both a term and a definition.", "error")
        return redirect(url_for("lecturer_glossary"))

    existing = GlossaryEntry.query.filter_by(lecturer_id=lecturer_id, term=term).first()
    if existing:
        existing.definition = definition
        existing.created_at = utc_now()
        flash("Term updated (same name already existed).", "success")
    else:
        db.session.add(
            GlossaryEntry(lecturer_id=lecturer_id, term=term, definition=definition)
        )
        flash("Term added.", "success")
    db.session.commit()
    return redirect(url_for("lecturer_glossary"))


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
        ensure_upload_dirs()
        db.create_all()
    app.run(debug=True)
