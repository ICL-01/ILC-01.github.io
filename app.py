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
    rows = db.execute("SELECT id FROM employees")
    if session["user_id"] in rows:
        return render_template("index.html", admin=1)
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
        rowsguests = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        rowsemployees = db.execute(
            "SELECT * FROM employees WHERE username = ?", request.form.get("username")
        )

        guest = int(request.form.get("guest"))

        if guest == 1:
            # Ensure username exists and password is correct
            if len(rowsguests) != 1 or not check_password_hash(
                rowsguests[0]["hash"], request.form.get("password")
            ):
                status_over = "Username or password are not correct."
                return render_template("login.html", username=username, password=password, status_over=status_over)
            # Remember which user has logged in
            session["user_id"] = rowsguests[0]["id"]

        else:
                # Ensure username exists and password is correct
            if len(rowsemployees) != 1 or not check_password_hash(
                rowsemployees[0]["hash"], request.form.get("password")
            ):
                status_over = "Username or password are not correct."
                return render_template("login.html", username=username, password=password, status_over=status_over)
            # Remember which user has logged in
            session["user_id"] = rowsemployees[0]["id"]
       

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
        guest = int(request.form.get("guest"))

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


        rowsguests = db.execute("SELECT * FROM users WHERE username = ?", username)
        rowsemployees = db.execute("SELECT * FROM employees WHERE username = ?", username)
        hash = generate_password_hash(password)

       
        #Check if user already exists
        if len(rowsguests) > 0 and guest == 1:
            status_equality = "There is an account with this username. Please choose another one."
            return render_template("register.html", username=username, password=password, confirmation=confirmation, status_equality=status_equality)
        if len(rowsemployees) > 0 and guest != 1:
            status_equality = "There is an account with this username. Please choose another one."
            return render_template("register.html", username=username, password=password, confirmation=confirmation, status_equality=status_equality)

        if guest == 1:
            db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, hash)
            rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        else:
            db.execute("INSERT INTO employees (username, hash, admin) VALUES (?,?)", username, hash, 1)
            rows = db.execute("SELECT * FROM employees WHERE username = ?", username)

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

@app.route("/passwordchange", methods=["GET", "POST"])
@login_required
def passwordchange():
    """Show settings"""

    if request.method == "POST":

        # Validate submission
        currentpassword = request.form.get("currentpassword")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure password == confirmation
        if not (newpassword == confirmation):
            status_equality = "Your passwords do not match."
            return render_template("passwordchange.html", status_equality=status_equality)

        # Ensure password not blank
        if currentpassword == "" or newpassword == "" or confirmation == "":
            status_equality = "You are missing some inputs."
            return render_template("passwordchange.html", status_equality=status_equality)

       # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], currentpassword):
            status_equality = "That was not your current password."
            return render_template("passwordchange.html", status_equality=status_equality)
        else:
            hashcode = generate_password_hash(newpassword, method='pbkdf2:sha256', salt_length=8)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", hashcode, session["user_id"])

        # Redirect user to settings
        return redirect("/settings")

    else:
        return render_template("passwordchange.html")
    
@app.route("/namechange",  methods=["GET", "POST"])
@login_required
def namechange():
    if request.method == "POST":
        name = request.form.get("currentname")
        newname = request.form.get("newname")

        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        if rows[0]["username"] != name:
            status_name = "That is not your actual username."
            return render_template("namechange.html", status_name=status_name)
        else:
            db.execute("UPDATE users SET username = ? WHERE id = ?", newname, session["user_id"])

        # Redirect user to settings
        return redirect("/settings")
    else:
        return render_template("namechange.html")

@app.route("/settings")
@login_required
def settings():
    """Show settings"""
    # Query database
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    return render_template("settings.html", username=username[0]['username'])

@app.route("/account")
@login_required
def account():
    """Show settings"""
    # Query database
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    return render_template("account.html", username=username[0]['username'])

@app.route("/bookings", methods=["GET", "POST"])
@login_required
def bookings():
    return render_template("bookings.html")

@app.route("/shop", methods=["GET","POST"])
@login_required
def shop():
    return render_template("shop.html")

@app.route("/aboutus")
def aboutus():
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    return render_template("aboutus.html", username=username[0]['username'])