import csv
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, make_response, redirect, render_template, request, send_from_directory, session, url_for
from sqlalchemy import func
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
    root = app.config["UPLOAD_FOLDER"]
    os.makedirs(os.path.join(root, "activities"), exist_ok=True)
    os.makedirs(os.path.join(root, "submissions"), exist_ok=True)
    os.makedirs(os.path.join(root, "pastpapers"), exist_ok=True)


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


class PastPaperUpload(db.Model):
    __tablename__ = "past_paper_upload"

    id = db.Column(db.Integer, primary_key=True)
    lecturer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


class ActivitySubmission(db.Model):
    __tablename__ = "activity_submission"
    __table_args__ = (
        db.UniqueConstraint(
            "activity_id",
            "student_id",
            name="uq_submission_activity_student",
        ),
    )

    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey("activity_upload.id"), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    stored_filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False, default=utc_now)


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
    submission_id = db.Column(
        db.Integer,
        db.ForeignKey("activity_submission.id"),
        nullable=True,
        unique=True,
        index=True,
    )
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


class Notification(db.Model):
    __tablename__ = "notification"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    activity_id = db.Column(
        db.Integer,
        db.ForeignKey("activity_upload.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    message = db.Column(db.String(500), nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


def notify_students_new_activity(activity: ActivityUpload) -> None:
    """Create an unread notification for every student when a lecturer uploads an activity."""
    lecturer = db.session.get(User, activity.lecturer_id)
    lecturer_name = lecturer.username if lecturer else "A lecturer"
    message = f'{lecturer_name} uploaded a new activity: "{activity.title}"'
    students = User.query.filter_by(role="student", is_blocked=False).all()
    for student in students:
        db.session.add(
            Notification(
                user_id=student.id,
                activity_id=activity.id,
                message=message,
            )
        )


def unread_notification_count(user_id: int) -> int:
    return Notification.query.filter_by(user_id=user_id, is_read=False).count()


def student_learning_progress(student_id: int) -> dict:
    """Activity completion only — not grades."""
    total = ActivityUpload.query.count()
    if total == 0:
        return {
            "total_activities": 0,
            "submitted_activities": 0,
            "completion_percentage": 0.0,
        }
    submitted = ActivitySubmission.query.filter_by(student_id=student_id).count()
    pct = round((submitted / total) * 100, 1)
    return {
        "total_activities": total,
        "submitted_activities": submitted,
        "completion_percentage": pct,
    }


def student_average_grade_percentage(student_id: int):
    """Mean of (score / max_score) * 100 across grade entries, or None if none."""
    grades = GradeEntry.query.filter_by(student_id=student_id).all()
    if not grades:
        return None
    ratios = []
    for grade in grades:
        if grade.max_score and grade.max_score > 0:
            ratios.append(grade.score / grade.max_score)
    if not ratios:
        return None
    return round((sum(ratios) / len(ratios)) * 100, 1)


def student_progress_context(student_id: int) -> dict:
    progress = student_learning_progress(student_id)
    return {
        **progress,
        "average_grade_percentage": student_average_grade_percentage(student_id),
    }


@app.context_processor
def inject_notification_count():
    if session.get("role") == "student" and session.get("user_id"):
        return {"unread_notification_count": unread_notification_count(session["user_id"])}
    return {"unread_notification_count": 0}


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
    student_id = session["user_id"]
    return render_template(
        "dashboard_student.html",
        username=session.get("username"),
        **student_progress_context(student_id),
    )


@app.route("/student/notifications")
@login_required
@role_required("student")
def student_notifications():
    student_id = session["user_id"]
    notifications = (
        Notification.query.filter_by(user_id=student_id)
        .order_by(Notification.created_at.desc())
        .all()
    )
    has_unread = any(not n.is_read for n in notifications)
    return render_template(
        "student_notifications.html",
        username=session.get("username"),
        notifications=notifications,
        has_unread=has_unread,
    )


@app.route("/student/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
@role_required("student")
def student_notification_mark_read(notification_id):
    note = db.session.get(Notification, notification_id)
    if not note or note.user_id != session["user_id"]:
        flash("Notification not found.", "error")
        return redirect(url_for("student_notifications"))
    note.is_read = True
    db.session.commit()
    return redirect(url_for("student_notifications"))


@app.route("/student/notifications/read-all", methods=["POST"])
@login_required
@role_required("student")
def student_notifications_mark_all_read():
    Notification.query.filter_by(
        user_id=session["user_id"],
        is_read=False,
    ).update({"is_read": True})
    db.session.commit()
    flash("All notifications marked as read.", "success")
    return redirect(url_for("student_notifications"))


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
    my_submissions = ActivitySubmission.query.filter_by(student_id=student_id).all()
    submissions_by_activity = {s.activity_id: s for s in my_submissions}

    return render_template(
        "student_resources.html",
        username=session.get("username"),
        activities=activities,
        grades=grades,
        glossary_terms=glossary_terms,
        lecturers_by_id=lecturers_by_id,
        submissions_by_activity=submissions_by_activity,
        **student_progress_context(student_id),
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
        db.session.flush()
        notify_students_new_activity(row)
        db.session.commit()
        flash("Activity PDF uploaded. All students were notified.", "success")
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


@app.route("/lecturer/pastpapers", methods=["GET", "POST"])
@login_required
@role_required("lecturer")
def lecturer_pastpapers():
    lecturer_id = session["user_id"]
    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        upload = request.files.get("file")
        if not title:
            flash("Please enter a title for this past paper.", "error")
            return redirect(url_for("lecturer_pastpapers"))
        if not upload or not upload.filename:
            flash("Please choose a PDF file to upload.", "error")
            return redirect(url_for("lecturer_pastpapers"))
        if not allowed_activity_filename(upload.filename):
            flash("Only PDF files are allowed.", "error")
            return redirect(url_for("lecturer_pastpapers"))

        ensure_upload_dirs()
        safe = secure_filename(upload.filename)
        if not safe:
            flash("Invalid file name.", "error")
            return redirect(url_for("lecturer_pastpapers"))
        stored = f"{uuid.uuid4().hex}_{safe}"
        dest_dir = os.path.join(app.config["UPLOAD_FOLDER"], "pastpapers", str(lecturer_id))
        os.makedirs(dest_dir, exist_ok=True)
        upload.save(os.path.join(dest_dir, stored))

        db.session.add(
            PastPaperUpload(
                lecturer_id=lecturer_id,
                title=title,
                stored_filename=stored,
                original_filename=upload.filename,
            )
        )
        db.session.commit()
        flash("Past paper uploaded.", "success")
        return redirect(url_for("lecturer_pastpapers"))

    papers = (
        PastPaperUpload.query.filter_by(lecturer_id=lecturer_id)
        .order_by(PastPaperUpload.created_at.desc())
        .all()
    )
    return render_template(
        "lecturer_pastpapers.html",
        username=session.get("username"),
        pastpapers=papers,
    )


@app.route("/lecturer/pastpapers/<int:paper_id>/download")
@login_required
@role_required("lecturer")
def lecturer_pastpaper_download(paper_id):
    row = db.session.get(PastPaperUpload, paper_id)
    lecturer_id = session["user_id"]
    if not row or row.lecturer_id != lecturer_id:
        flash("File not found.", "error")
        return redirect(url_for("lecturer_pastpapers"))
    folder = os.path.join(app.config["UPLOAD_FOLDER"], "pastpapers", str(lecturer_id))
    return send_from_directory(
        folder,
        row.stored_filename,
        as_attachment=True,
        download_name=row.original_filename,
    )


@app.route("/student/pastpapers")
@login_required
@role_required("student")
def student_pastpapers():
    papers = PastPaperUpload.query.order_by(PastPaperUpload.created_at.desc()).all()
    lecturers = User.query.filter_by(role="lecturer").all()
    lecturers_by_id = {u.id: u for u in lecturers}
    return render_template(
        "student_pastpapers.html",
        username=session.get("username"),
        pastpapers=papers,
        lecturers_by_id=lecturers_by_id,
    )


@app.route("/student/pastpapers/<int:paper_id>/download")
@login_required
@role_required("student")
def student_pastpaper_download(paper_id):
    row = db.session.get(PastPaperUpload, paper_id)
    if not row:
        flash("File not found.", "error")
        return redirect(url_for("student_pastpapers"))
    folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "pastpapers",
        str(row.lecturer_id),
    )
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


@app.route("/student/activities/<int:activity_id>/submit", methods=["POST"])
@login_required
@role_required("student")
def student_activity_submit(activity_id):
    student_id = session["user_id"]
    activity = db.session.get(ActivityUpload, activity_id)
    if not activity:
        flash("Activity not found.", "error")
        return redirect(url_for("student_resources"))

    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Please choose a PDF answer file.", "error")
        return redirect(url_for("student_resources"))
    if not allowed_activity_filename(upload.filename):
        flash("Only PDF files are allowed.", "error")
        return redirect(url_for("student_resources"))

    ensure_upload_dirs()
    safe = secure_filename(upload.filename)
    if not safe:
        flash("Invalid file name.", "error")
        return redirect(url_for("student_resources"))
    stored = f"{uuid.uuid4().hex}_{safe}"
    dest_dir = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "submissions",
        str(activity_id),
        str(student_id),
    )
    os.makedirs(dest_dir, exist_ok=True)
    upload.save(os.path.join(dest_dir, stored))

    existing = ActivitySubmission.query.filter_by(
        activity_id=activity_id,
        student_id=student_id,
    ).first()
    if existing:
        existing.stored_filename = stored
        existing.original_filename = upload.filename
        existing.submitted_at = utc_now()
        flash("Answer updated (re-submitted).", "success")
    else:
        db.session.add(
            ActivitySubmission(
                activity_id=activity_id,
                student_id=student_id,
                stored_filename=stored,
                original_filename=upload.filename,
            )
        )
        flash("Answer submitted.", "success")
    db.session.commit()
    return redirect(url_for("student_resources"))


@app.route("/student/submissions/<int:submission_id>/download")
@login_required
@role_required("student")
def student_submission_download(submission_id):
    sub = db.session.get(ActivitySubmission, submission_id)
    if not sub or sub.student_id != session["user_id"]:
        flash("Submission not found.", "error")
        return redirect(url_for("student_resources"))
    folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "submissions",
        str(sub.activity_id),
        str(sub.student_id),
    )
    return send_from_directory(
        folder,
        sub.stored_filename,
        as_attachment=True,
        download_name=sub.original_filename,
    )


def _lecturer_activity_or_none(activity_id: int, lecturer_id: int):
    activity = db.session.get(ActivityUpload, activity_id)
    if not activity or activity.lecturer_id != lecturer_id:
        return None
    return activity


def _submission_counts_for_lecturer(lecturer_id: int) -> dict[int, int]:
    rows = (
        db.session.query(ActivitySubmission.activity_id, func.count(ActivitySubmission.id))
        .join(ActivityUpload, ActivitySubmission.activity_id == ActivityUpload.id)
        .filter(ActivityUpload.lecturer_id == lecturer_id)
        .group_by(ActivitySubmission.activity_id)
        .all()
    )
    return {activity_id: count for activity_id, count in rows}


def _grades_for_activity_submissions(lecturer_id: int, activity_id: int):
    """Map submission_id -> GradeEntry for one activity."""
    submission_ids = [
        s.id
        for s in ActivitySubmission.query.filter_by(activity_id=activity_id).all()
    ]
    if not submission_ids:
        return {}
    grades = GradeEntry.query.filter(
        GradeEntry.lecturer_id == lecturer_id,
        GradeEntry.submission_id.in_(submission_ids),
    ).all()
    return {g.submission_id: g for g in grades}


@app.route("/lecturer/submissions")
@login_required
@role_required("lecturer")
def lecturer_submissions():
    lecturer_id = session["user_id"]
    activities = (
        ActivityUpload.query.filter_by(lecturer_id=lecturer_id)
        .order_by(ActivityUpload.created_at.desc())
        .all()
    )
    submission_counts = _submission_counts_for_lecturer(lecturer_id)

    return render_template(
        "lecturer_submissions.html",
        username=session.get("username"),
        activities=activities,
        submission_counts=submission_counts,
    )


@app.route("/lecturer/submissions/activity/<int:activity_id>")
@login_required
@role_required("lecturer")
def lecturer_submissions_activity(activity_id):
    lecturer_id = session["user_id"]
    activity = _lecturer_activity_or_none(activity_id, lecturer_id)
    if not activity:
        flash("Activity not found.", "error")
        return redirect(url_for("lecturer_submissions"))

    submissions = (
        ActivitySubmission.query.filter_by(activity_id=activity_id)
        .order_by(ActivitySubmission.submitted_at.desc())
        .all()
    )
    students = User.query.filter_by(role="student").all()
    students_by_id = {u.id: u for u in students}
    grades_by_submission = _grades_for_activity_submissions(lecturer_id, activity_id)

    return render_template(
        "lecturer_submissions_activity.html",
        username=session.get("username"),
        activity=activity,
        submissions=submissions,
        students_by_id=students_by_id,
        grades_by_submission=grades_by_submission,
    )


@app.route("/lecturer/submissions/activity/<int:activity_id>/grades.csv")
@login_required
@role_required("lecturer")
def lecturer_activity_grades_csv(activity_id):
    lecturer_id = session["user_id"]
    activity = _lecturer_activity_or_none(activity_id, lecturer_id)
    if not activity:
        flash("Activity not found.", "error")
        return redirect(url_for("lecturer_submissions"))

    submissions = (
        ActivitySubmission.query.filter_by(activity_id=activity_id)
        .order_by(ActivitySubmission.submitted_at.asc())
        .all()
    )
    students_by_id = {u.id: u for u in User.query.filter_by(role="student").all()}
    grades_by_submission = _grades_for_activity_submissions(lecturer_id, activity_id)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "activity_title",
            "student_username",
            "submitted_at",
            "answer_filename",
            "score",
            "max_score",
            "percentage",
            "graded_at",
            "status",
        ]
    )
    for sub in submissions:
        stu = students_by_id.get(sub.student_id)
        grade = grades_by_submission.get(sub.id)
        submitted = (
            sub.submitted_at.strftime("%Y-%m-%d %H:%M")
            if sub.submitted_at
            else ""
        )
        if grade:
            pct = round((grade.score / grade.max_score) * 100, 1) if grade.max_score else ""
            graded_at = (
                grade.created_at.strftime("%Y-%m-%d %H:%M")
                if grade.created_at
                else ""
            )
            writer.writerow(
                [
                    activity.title,
                    stu.username if stu else sub.student_id,
                    submitted,
                    sub.original_filename,
                    grade.score,
                    grade.max_score,
                    pct,
                    graded_at,
                    "graded",
                ]
            )
        else:
            writer.writerow(
                [
                    activity.title,
                    stu.username if stu else sub.student_id,
                    submitted,
                    sub.original_filename,
                    "",
                    "",
                    "",
                    "",
                    "not_graded",
                ]
            )

    safe_title = secure_filename(activity.title) or f"activity_{activity_id}"
    filename = f"grades_{safe_title}.csv"
    response = make_response("\ufeff" + buf.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@app.route("/lecturer/submissions/<int:submission_id>/download")
@login_required
@role_required("lecturer")
def lecturer_submission_download(submission_id):
    sub = db.session.get(ActivitySubmission, submission_id)
    if not sub:
        flash("Submission not found.", "error")
        return redirect(url_for("lecturer_submissions"))
    activity = db.session.get(ActivityUpload, sub.activity_id)
    if not activity or activity.lecturer_id != session["user_id"]:
        flash("Submission not found.", "error")
        return redirect(url_for("lecturer_submissions"))
    folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "submissions",
        str(sub.activity_id),
        str(sub.student_id),
    )
    return send_from_directory(
        folder,
        sub.stored_filename,
        as_attachment=True,
        download_name=sub.original_filename,
    )


@app.route("/lecturer/submissions/<int:submission_id>/grade", methods=["POST"])
@login_required
@role_required("lecturer")
def lecturer_grade_submission(submission_id):
    lecturer_id = session["user_id"]
    sub = db.session.get(ActivitySubmission, submission_id)
    if not sub:
        flash("Submission not found.", "error")
        return redirect(url_for("lecturer_submissions"))
    activity = db.session.get(ActivityUpload, sub.activity_id)
    if not activity or activity.lecturer_id != lecturer_id:
        flash("Submission not found.", "error")
        return redirect(url_for("lecturer_submissions"))
    activity_url = url_for("lecturer_submissions_activity", activity_id=activity.id)

    score_raw = (request.form.get("score") or "").strip()
    max_raw = (request.form.get("max_score") or "").strip()
    try:
        score = float(score_raw)
    except ValueError:
        flash("Score must be a number.", "error")
        return redirect(activity_url)
    max_score = 100.0
    if max_raw != "":
        try:
            max_score = float(max_raw)
        except ValueError:
            flash("Max score must be a number.", "error")
            return redirect(activity_url)

    assignment_name = activity.title
    grade = GradeEntry.query.filter_by(submission_id=submission_id).first()
    if not grade:
        grade = GradeEntry.query.filter_by(
            lecturer_id=lecturer_id,
            student_id=sub.student_id,
            assignment_name=assignment_name,
        ).first()
    if grade:
        grade.score = score
        grade.max_score = max_score
        grade.submission_id = submission_id
        grade.created_at = utc_now()
        flash("Grade updated for this submission.", "success")
    else:
        db.session.add(
            GradeEntry(
                lecturer_id=lecturer_id,
                student_id=sub.student_id,
                assignment_name=assignment_name,
                score=score,
                max_score=max_score,
                submission_id=submission_id,
            )
        )
        flash("Grade saved for this submission.", "success")
    db.session.commit()
    return redirect(activity_url)


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
