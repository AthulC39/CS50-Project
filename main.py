import os
from pathlib import Path
from flask import Flask,flash, redirect, render_template, request, session
from flask_session import Session
from flask_mysqldb import MySQL
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from assistants import apology, login_required
import mysql.connector
import mysql

app = Flask(__name__)


app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['MYSQL_DB'] = 'cs50_project'

Session(app)


app.secret_key = "asddaskhdvasdkhv"



mysql = MySQL(app)




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
        db = mysql.connection.cursor()
        db.execute("SELECT username FROM students WHERE id = 1")
        sesh = db.fetchall()
        mysql.connection.commit()

        return render_template('dashboard.html',sesh=sesh)
    else:
        db = mysql.connection.cursor()
        db.execute("SELECT username FROM students WHERE id = 1")
        sesh = db.fetchall()
        mysql.connection.commit()
        return render_template('dashboard.html',sesh=sesh)



@app.route('/login',methods=['GET','POST'])
def login():

    session.clear()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = mysql.connection.cursor()
        db.execute("SELECT * FROM students WHERE username = %s",[username])
        rows = db.fetchall()
        mysql.connection.commit()
        db.close()
        if len(rows) != 1:
            return apology("error",400)

        if check_password_hash(rows[0][3], password):
            session["user_id"] = rows[0][0]
            return redirect('/')



    else:
        return render_template('login.html')

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user """
    # clear session
    session.clear()

    # check if form submitted via POST
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        db = mysql.connection.cursor()
        db.execute("SELECT * FROM students WHERE username = %s",[username])
        rows = db.fetchall()
        # verify the user input in both username and password field
        if len(rows) > 0:
            return apology("Username already in use",400)
        elif not username:
            return apology("Please fill in username form please.", 400)
        elif not password:
            return apology("Please fill in password form please.", 400)
        elif not confirmation:
            return apology("Please fill in confirmation form please.", 400)
        elif password != confirmation:
            return apology("Passwords do not match, please try again", 400)

        # hashes the password
        hash = generate_password_hash(request.form.get("password"), method='sha256', salt_length=16)

        # store hashed password in database
        db.execute("INSERT INTO students (username, hash) VALUES (%s, %s)",(username,hash))
        mysql.connection.commit()

        return redirect("/")

    else:
        return render_template("register.html")


if __name__ == '__main__':
    app.run(debug=True)

