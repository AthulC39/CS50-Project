from flask import Flask,flash, redirect, render_template, request, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SQLALCHEMY_DATABASE_URI"] =''
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

Session(app)
def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route('/',methods=['GET','POST'])
@login_required
def home():
    if request.method == 'POST':


        return render_template('dashboard.html')
    else:
        return render_template('dashboard.html')



@app.route('/login',methods=['GET','POST'])
def login():

    session.clear()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

    rows = db.execute("SELECT * FROM users WHERE username = :session_id",session_id=username)

    if len(rows) != 1:
        return "ERROR 403"

    if check_password_hash(rows[0]["hash"], password) == True:
        session["user_id"] = rows[0]["id"]
        return redirect('/')

    else:
        render_template('login.html')


if __name__ == '__main__':
    app.run()