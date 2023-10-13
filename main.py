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


        return render_template('dashboard.html')
    else:
        db = mysql.connection.cursor()
        db.execute("SELECT * FROM students WHERE id = 1")
        sesh = db.fetchall()
        username = (sesh[0][1])
        mysql.connection.commit()
        db.execute("SELECT * FROM marks WHERE markid = 1")
        marks = db.fetchall()
        studentMarks = marks[0]
        return render_template('dashboard.html',username=username,marks=studentMarks)

@app.route('/assignments',methods=['GET','POST'])
@login_required
def assignments():
    if request.method == 'POST':

        return render_template('submit.html')
    else:


        return render_template('assignments.html')

@app.route('/submit',methods=['GET','POST'])
@login_required
def submit():
    if request.method == 'POST':
        assignment_name=request.form.get('aName')
        class_name=request.form.get('class')
        file = request.form.get('file')
        db = mysql.connection.cursor()
        db.execute("INSERT INTO assignments (name,class,file) VALUES (%s,%s,%s)",[assignment_name,class_name,str(file)])
        mysql.connection.commit()
        db.close()
        flash('Assignment submitted sucessfully!')
        return redirect('/assignments')
    else:


        return render_template('submit.html')



@app.route('/forum',methods=['GET','POST'])
@login_required
def forum():


    if request.method == 'POST':


        return render_template('forum.html')
    else:
        db = mysql.connection.cursor()
        mysql.connection.commit()
        db.execute("SELECT COUNT(commentid) FROM comments")
        count = db.fetchall()
        return render_template('forum.html',count=count)

@app.route('/post1',methods=['GET','POST'])
@login_required
def post1():
    if request.method == 'POST':
        text = request.form.get('post1')
        db = mysql.connection.cursor()
        db.execute("SELECT username FROM students WHERE id = 1")
        sesh = db.fetchall()
        mysql.connection.commit()
        db.execute("SELECT COUNT(commentid) FROM comments")
        count = db.fetchall()
        temp = count[0][0] + 1
        db.execute("INSERT INTO comments VALUES (%s,%s,%s)",[str(temp),text,sesh[0][0]])

        mysql.connection.commit()
        db.close()

        return redirect("post1")
    else:

        db = mysql.connection.cursor()
        db.execute("SELECT username FROM students WHERE id = 1")
        sesh = db.fetchall()
        mysql.connection.commit()


        db.execute("SELECT * FROM comments")
        posts = db.fetchall()
        mysql.connection.commit()
        db.execute("SELECT COUNT(commentid) FROM comments")
        count = db.fetchall()
        mysql.connection.commit()
        db.close()
        return render_template('post1.html',user=sesh,posts=posts,count=count)

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

