from flask import Flask,flash, redirect, render_template, request, session
from flask_session import Session
from flask_mysqldb import MySQL
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import insert, update, select
import mysql.connector
import mysql

app = Flask(__name__)
Session(app)






mysql = MySQL(app)

def login_required(f):
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
def home():

    db = mysql.connection.cursor()
    db.execute("SELECT id FROM test")
    names=db.fetchall()
    mysql.connection.commit()
    db.close()
    if request.method == 'POST':

        return render_template('dashboard.html',names=names)
    else:

        return render_template('dashboard.html',names=names)



@app.route('/login',methods=['GET','POST'])
def login():

    session.clear()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = mysql.connection.cursor()
        rows = db.execute("SELECT * FROM users WHERE username = %s",username)
        mysql.connection.commit()
        db.close()
        if len(rows) != 1:
            return "ERROR 403"

        if check_password_hash(rows[0]["hash"], password):
            session["user_id"] = rows[0]["id"]
            return redirect('/')

    else:
        render_template('login.html')


if __name__ == '__main__':
    app.run(debug=True)

