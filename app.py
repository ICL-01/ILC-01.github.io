import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import  login_required


# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///dentos.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # Ensure username was submitted
        if not username:
            status_username = "Username is missing. Please provide your username."
            if not password:
                status_password = "Please provide your password."
                return render_template("login.html", status_username=status_username, status_password=status_password)
            else:
                return render_template("login.html", password=password, status_username=status_username)

        # Ensure password was submitted
        elif not request.form.get("password"):
            status_password = "Please provide your password."
            return render_template("login.html", username=username, status_password=status_password)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            status_over = "Username or password are not correct."
            return render_template("login.html", username=username, password=password, status_over=status_over)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            status_username = "Missing Username."
            if not password:
                status_password = "Password missing."
                if not confirmation:
                    status_equality = "Missing Confirmation"
                    return render_template("register.html", status_username = status_username, status_password=status_password, status_equality=status_equality)
                else:
                    return render_template("register.html", status_username = status_username, status_password=status_password)
            else:
                if not confirmation:
                    status_equality = "Missing Confirmation"
                    return render_template("register.html", status_username=status_username, password=password, status_equality=status_equality)
                else:
                    if confirmation != password:
                        status_equality="Passwords do not match."
                        return render_template("register.html", status_username = status_username, password=password, confirmation=confirmation, status_equality=status_equality)
                    else:
                        return render_template("register.html", status_username = status_username, password=password, confirmation=confirmation)
        else:
            if not password:
                status_password = "Password missing."
                if not confirmation:
                    status_equality = "Missing Confirmation"
                    return render_template("register.html", username=username, status_password=status_password, status_equality=status_equality)
                else:
                    return render_template("register.html", username=username, status_password=status_password)
            else:
                if not confirmation:
                    status_equality = "Missing Confirmation"
                    return render_template("register.html", username=username, password=password, status_equality=status_equality)
                else:
                    if confirmation != password:
                        status_equality="Passwords do not match."
                        return render_template("register.html", username=username, password=password, confirmation=confirmation, status_equality=status_equality)


        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        #Check if user already exists
        if len(rows) > 0:
            status_equality = "There is an account with this username. Please choose another one."
            return render_template("register.html", username=username, password=password, confirmation=confirmation, status_equality=status_equality)

        hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, hash)
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("register.html")
    

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")