from flask import Flask, render_template, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from markupsafe import escape
import re

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firstapp.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # Needed for CSRF protection
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

class Firstapp(db.Model):
    sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)

@app.route("/", methods=["GET", "POST"])
def hello_world():
    if request.method == "POST":
        fname = escape(request.form.get('fname', '').strip())
        lname = escape(request.form.get('lname', '').strip())
        email = escape(request.form.get('email', '').strip())
        if fname and lname and email:
            person = Firstapp(fname=fname, lname=lname, email=email)
            db.session.add(person)
            db.session.commit()
    allpeople = Firstapp.query.all()
    return render_template('index.html', allpeople=allpeople)

@app.route("/update/<int:sno>", methods=["GET", "POST"])
def update(sno):
    person = Firstapp.query.filter_by(sno=sno).first()
    if request.method == "POST":
        person.fname = escape(request.form['fname'])
        person.lname = escape(request.form['lname'])
        person.email = escape(request.form['email'])
        db.session.commit()
        return redirect("/")
    return render_template('update.html', allpeople=person)

@app.route("/delete/<int:sno>")
def delete(sno):
    person = Firstapp.query.filter_by(sno=sno).first()
    db.session.delete(person)
    db.session.commit()
    return redirect("/")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = escape(request.form.get("email", "").strip())
        password = request.form.get("password", "").strip()

        email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_regex, email):
            flash("Invalid email format", "danger")
            return redirect("/login")
        if len(password) < 8:
            flash("Password too short", "danger")
            return redirect("/login")

        # Simulated hash check (use real user lookup + hash check here)
        dummy_hash = bcrypt.generate_password_hash("secure1234").decode("utf-8")
        if bcrypt.check_password_hash(dummy_hash, password):
            session['user'] = email
            return redirect("/home")
        flash("Invalid login", "danger")
    return render_template("login.html")

@app.route("/contacts", methods=["GET", "POST"])
def contacts():
    if request.method == "POST":
        name = escape(request.form.get("name", "").strip())
        email = escape(request.form.get("email", "").strip())
        website = escape(request.form.get("website", "").strip())

        name_pattern = re.compile(r"^[a-zA-Z\s\-']{2,50}$")
        email_pattern = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$")
        website_pattern = re.compile(r"^$|^(https?:\/\/)?([\w\-]+\.)+[\w\-]{2,}(\/[\w\-._~:\/?#\[\]@!$&'()*+,;=]*)?$")

        errors = []
        if not name or not name_pattern.fullmatch(name):
            errors.append("Invalid name.")
        if not email or not email_pattern.fullmatch(email):
            errors.append("Invalid email.")
        if website and not website_pattern.fullmatch(website):
            errors.append("Invalid website URL.")

        if errors:
            return render_template("contacts.html", errors=errors, form_data={"name": name, "email": email, "website": website})

        return f"Thank you {name}, we've received your info!"

    return render_template("contacts.html", errors=None, form_data={"name": "", "email": "", "website": ""})

# Custom Error Pages
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)