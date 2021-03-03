import os
from datetime import datetime
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Stocks is a list of dictionaries
    stocks = db.execute("SELECT type,symbol,SUM(shares) shares,price FROM transactions WHERE id=:id GROUP BY symbol,type=:type",id=session["user_id"],type="sell")
    # bought = db.execute("SELECT type,symbol,SUM(shares) shares,price FROM transactions WHERE id=:id GROUP BY symbol,type=:type",id=session["user_id"],type="buy")
    print("stocks= ",stocks)
    # stocks=  [{'type': 'buy', 'symbol': 'AMZN', 'shares': 1, 'price': 3146.14}, {'type': 'buy', 'symbol': 'NFLX', 'shares': 4, 'price': 550.64}, {'type': 'sell', 'symbol': 'NFLX', 'shares': 1, 'price': 550.64}]
    # print("sold= ",bought)
    # sold=  [{'type': 'buy', 'symbol': 'AMZN', 'shares': 1, 'price': 3146.14}, {'type': 'sell', 'symbol': 'NFLX', 'shares': 1, 'price': 550.64}, {'type': 'buy', 'symbol': 'NFLX', 'shares': 4, 'price': 550.64}]

    # print(len(stocks))
    user = db.execute("SELECT cash FROM users WHERE id=:id",id=session["user_id"])
    # if stocks:
    for i in range(len(stocks)):

        # i reaches the length of the list because after a dictionary was deleted and decremented, we go through the same stock value but we go to the else clause.
        if i == len(stocks):
            break

        if stocks[i]["type"]=='buy':

            dic = lookup(stocks[i]["symbol"])
            stocks[i]["name"] = dic["name"]
            stocks[i]["price"] = usd(dic["price"])

            # Accordingly for some reason the type sell comes after buy based on th GROUP BY for each symbol
            if i+1 < len(stocks) and stocks[i+1]["type"] == 'sell' and stocks[i+1]["symbol"] == dic["symbol"]:

                stocks[i]["shares"] -= stocks[i+1]["shares"] # Decreasing the value of the shares if sold
                stocks[i]["totalprice"] = usd(dic["price"] * stocks[i]["shares"]) # creating a key-value pair and updating it with the total price
                del stocks[i+1] # need to delete this sell row from the dictionary because we are passing this list of dictionaries to the index template
                i-=1

            else:
                stocks[i]["totalprice"] = usd(dic["price"] * stocks[i]["shares"])
        else:
            continue

    # removing any dictionaries with 0 shares as there is no point of showing what shares you HAD
    for i in range(len(stocks)):
        if i == len(stocks):
            break
        elif stocks[i]["shares"] == 0:
            del stocks[i]
            i-=1

    print(stocks)
    return render_template("index.html",transactions=stocks, newcash=usd(user[0]["cash"]), oldcash=usd(10000))
    # else:
    #     return apology("Unable to provide your breakdown",400)


@app.route("/change_password",methods=["GET","POST"])
@login_required
def password_change():
    error=None
    # if request.method == "GET":
    #     return render_template("password.html")
    if request.method== "POST":
        if not request.form.get("password-first") or not request.form.get("password-second"):
            error="incomplete input"
            return render_template("password.html", error=error)
            # return apology("You did not complete all fields",400)
        elif request.form.get("password-first") != request.form.get("password-second"):
            error = "passwords do not match"
            return render_template("password.html", error=error)
            # return apology("Passwords do not match",400)

        user_password = db.execute("SELECT hash FROM users WHERE id=:id",id=session["user_id"])[0]["hash"]#obtaining the hashed password that the user currently has
        # print(user_password)
        # check_password_hash(rows[0]["hash"], request.form.get("password")

        # Checking the hash of the password.
        if check_password_hash(user_password,request.form.get("password-first")):
            print("password check working")
            error="please use a new password"
            return render_template("password.html", error=error)
            # return apology("Password is used. Please enter a new password",400)
        # UPDATE users SET cash=:cash WHERE id=:id",id=session["user_id"], cash=users_cash[0]["cash"] - total_price)
        else:
            new_password=request.form.get("password-first")
            regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')

            #rules list will return either True or strings
            rules=[
                lambda s:any(x.isupper() for x in new_password) or 'uppercase characters',
                lambda s:any(x.islower() for x in new_password) or 'lowercase characters',
                lambda s:any(x.isdigit() for x in new_password) or 'digits',
                lambda s:True if (regex.search(new_password)==None) else 'special characters',
                lambda s:len(new_password)>=5 or 'number of characters greater than 5'
                ]
            #obtaining only the strings if true then it is ignored as it is one of the conditions that are satisfied
            problems = [p for p in [r(new_password) for r in rules] if p!=True]
            #ensuring that the password is legit!
            if len(problems)>0:
                error = 'You did not include any of the following: ' + ', '.join(problems)
                return render_template("password.html",error=error)
            # success
            else:
                new_password = generate_password_hash(request.form.get("password-first"))
                db.execute("UPDATE users SET hash=:hash WHERE id=:id",id=session["user_id"],hash=new_password)
                return render_template("login.html")
    return render_template("password.html", error=error)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("You did not provide a symbol",400)

        elif not lookup(request.form.get("symbol").upper()):
            return apology("Invalid stock symbol entered", 400)

        elif not request.form.get("shares") or int(request.form.get("shares"))<1:
            return apology("Invalid shares",400)

        # dic_buy = {}
        shares = int(request.form.get("shares"))

        #obtaining the dictionary fromm lookup in helpers.py
        dic_buy = lookup(request.form.get("symbol"))
        price = dic_buy["price"]
        total_price = price * shares
        name = dic_buy["name"]

        users_cash = db.execute("SELECT cash FROM users WHERE id=:id",id=session["user_id"])
        if total_price > users_cash[0]["cash"]:
            return apology("You have insufficient funds",400)

        db.execute("UPDATE users SET cash=:cash WHERE id=:id",id=session["user_id"], cash=users_cash[0]["cash"] - total_price)

        db.execute("INSERT INTO transactions (id, type, symbol,shares, price,time) VALUES (:id,:transaction_type,:symbol,:shares,:price,:time)",
            id = session["user_id"],
            transaction_type = "buy",
            symbol = request.form.get("symbol").upper(),#setting to upper because SQL doesn't distinguish letter case
            shares = int(request.form.get("shares")),
            price = total_price,
            time = datetime.now().strftime("%m/%d/%Y %H:%M:%S"))


        flash(f"You just bought {shares} shares from {name} worth {total_price} ")
        # flash("Bought")
        return redirect('/') # redirecting user to homepage

    else:
        return render_template("buy.html")

    # return apology("TODO")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    if(len(username)<1):
        return jsonify(True)
    check = db.execute("SELECT username FROM users WHERE username=:username",username=username)

    if(len(check)==0):
        return jsonify(True)
    else:
        return jsonify(False)

    return jsonify("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE id=:id",id=session["user_id"])
    for i in range(len(transactions)):
        dic = lookup(transactions[i]["symbol"])
        transactions[i]["name"] = dic["name"]
        transactions[i]["price"] = usd(dic["price"])

    return render_template("history.html",transactions=transactions)

    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        # Query database for username

        print(rows)
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":

        input_symbol = request.form.get("symbol")
        # Checking if the stock symbol is valid
        if not input_symbol:
            return apology("Symbol not found",400)

        elif not lookup(input_symbol):
            return apology("Invalid Stock Symbol",400)

        # creating a dictionary because lookup returns a dictionary with key-value pairs of stock name, price and symbol
        # quote_dic = {}
        quote_dic = lookup(input_symbol)
        # passing the values to the quoted.html file as it is written with jinja
        return render_template("quoted.html", name=quote_dic["name"], symbol=quote_dic["symbol"], price=usd(quote_dic["price"]))

    # if the method is not post
    else:
        return render_template("quote.html")

    # return apology("No input entered",400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not request.form.get('username'):
            return apology("must provide username", 403)

        # rows = db.execute("SELECT id FROM users WHERE username = :username", username=request.form.get("username"))

        # elif rows == None:
        #   return apology("username already exists", 400)

       # Check if any of the password inputs are blank or if the passwords do not match
        elif not request.form.get("password-first") or not request.form.get("password-second"):
            return apology("You did not provide a password",400)

        elif request.form.get("password-first") != request.form.get("password-second"):
            return apology("Passwords do not match",400)

       # Obtaining the hashed password
        hash_password = generate_password_hash(request.form.get("password-first"))

       # Inserting the newly registered user into the database. :username is a placeholder in SQL to prevent SQL injection attacks.
        new_user = db.execute("INSERT INTO users (username,hash) VALUES (:username, :hash)", username = request.form.get("username"), hash = hash_password)

        if new_user == None:
            return apology("Username already exists", 400)

       # remembers the user by the Large Integer
        session["user_id"] = new_user

       # providing a feedback. login.html will show the flashed message
        flash("You have successfully registered")
        return render_template("login.html")
       # After registering you directly enter into the login webpage

    # if route is GET
    else:
        return render_template("register.html")

    return apology("You haven't registered successfully", 403)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("You did not provide a stock symbol", 400)

        elif not lookup(request.form.get("symbol")):
            return apology("You did not provide a valid stock symbol",400)

        elif not request.form.get("shares"):
            return apology("You did not provide shares",400)

        elif int(request.form.get("shares")) >= 1:
            # this db.execute fn will return a dictionary of {'shares':x}
            my_shares = (db.execute("SELECT SUM(shares) shares FROM transactions WHERE id=:id GROUP BY :symbol",id=session["user_id"],symbol=request.form.get("symbol").upper()))[0]["shares"]
            # print(shares,type(shares))
            dic = lookup(request.form.get("symbol"))
            name = dic["name"]
            share_request = int(request.form.get("shares"))

            # If the number of shares the user wants to sell is higher than the number of shares that the user currently has
            if share_request > my_shares:
                return apology(f"You do not have {share_request} shares of {name} to sell",400)

            else:
                # added_price = dic["price"] * share_request # stock price * number of shares willing to be sold
                user_cash = (db.execute("SELECT cash FROM users WHERE id=:id",id=session["user_id"]))[0]["cash"] # obtaining the current cash
                new_cash = user_cash + dic["price"] * share_request # once sold the amount of each stock*shares is added to the user's total cost
                db.execute("UPDATE users SET cash=:cash WHERE id=:id",id=session["user_id"],cash=new_cash)#updating the user's cash balance
                #adding a new transaction into the transaction table
                db.execute("INSERT INTO transactions (id,type,symbol,shares,price,time) VALUES (:id,:transaction_type,:symbol,:shares,:price,:time)",
                    id=session["user_id"],
                    transaction_type="sell",
                    symbol = dic["symbol"].upper(),# storing all symbols in uppercase for index.html
                    shares=share_request,
                    price=dic["price"]*share_request,
                    time=datetime.now().strftime("%m/%d/%Y %H:%M:%S"))

            flash(f'You just sold {share_request} shares of {name} worth {usd(dic["price"]*share_request)}')
            return redirect('/') # redirecting user to homepage

        else:
            return apology("You have specified shares less than 1", 400)

    return render_template("sell.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


# if __name__ == "__main__":
#     app.run(debug=True)
