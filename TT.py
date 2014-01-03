import datetime
import json
import os
from pymongo import Connection
from bson import json_util
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, make_response, Response

from flask.ext.login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin, confirm_login
from flask.ext.httpauth import HTTPBasicAuth
import sys


class User(UserMixin):


    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.weeks = []

    def __init__(self, username, password, weeks):
        self.username = username
        self.password = password
        self.weeks = weeks

    def get_id(self):
        return unicode(str(self.username))

    def save_user_only(self):
        collection = User._getcol()
        finding = collection.insert({'name': self.username, 'password': self.password, 'weeks': []})

    @staticmethod
    def _getcol():
        uri = mongodb_uri()
        conn = Connection(uri)
        collection = conn.db.user_data
        return collection

    @staticmethod
    def get(username):
        collection = User._getcol()
        finding = collection.find_one({'name': username})

        # is_found = finding.count() > 0
        # weeknum = datetime.date.today().isocalendar()[1]
        # curr = finding["weeks"][weeknum]

        if finding is not None:
            print finding
            return User(finding["name"], finding["password"], finding["weeks"])
        else:
            return None

    @staticmethod
    def check_login(username, password):
        collection = User._getcol()
        finding = collection.find_one({'name': username, 'password': password})

        # is_found = finding.count() > 0
        # weeknum = datetime.date.today().isocalendar()[1]
        # curr = finding["weeks"][weeknum]

        if finding is not None:
            print finding
            return User(finding["name"], finding["password"], finding["weeks"])
        else:
            return None
    @staticmethod
    def get_password(username):
        collection = User._getcol()
        finding = collection.find_one({'name': username})
        if finding is not None:
            print finding
            return finding["password"]
        else:
            return None



application = app = Flask(__name__)

SECRET_KEY = "KJ&DKJEu*&he58*9fhsHh9f8y8"

app.debug=True

app.config.from_object(__name__)

auth = HTTPBasicAuth()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"

data_example = [{"week": 1, "days": [{"day": "mon", "in": 00, "out": 00}]}, {"week": 2, "days": [{"day": "sat", "in": 00, "out": 00}]}, {"week": 3, "days": [{"day": "tue", "in": 00, "out": 00}]}]


@auth.get_password
def get_password(name):
    pswd = User.get_password(name)
    if pswd is not None:
        user = User.check_login(name, pswd)
        login_user(user)
        return pswd
    return None

# @auth.verify_password(password)

@auth.error_handler
def unauthorized():
    return make_response(jsonify( { 'error': 'Unauthorized access' } ), 401)

@login_manager.user_loader
def load_user(username):

    return User.get(username)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/main")
@login_required
def main():

    return render_template("main.html", data=dta)

@app.route("/upload", methods=["POST", "GET"])
@login_required
def uploadf():

    # def save_upload(filename):
    #     if request.files.get('file'):
    #         mongo.save_file(filename, request.files['file'])
    #         return redirect(url_for('get_upload', filename=filename))
    # return render_template('upload.html', filename=filename)
    if request.method == 'POST':
        # TODO check file
        file = request.files['file']
        # TODO check file name
        filename = file.filename
        dir = os.path.dirname(__file__)
        file_dir = os.path.join(dir, 'tmp/')

        file.save(os.path.join(file_dir, filename))
        return redirect(url_for('main'))

    elif request.method == "GET":
        return render_template("uploadts.html")

@app.route("/download", methods=["GET"])
@login_required
def downloadf():

    dir = os.path.dirname(__file__)
    file_dir = os.path.join(dir, 'tmp/hellop.txt')

    response = make_response(file_dir)

    response.headers["Content-Disposition"] = "attachment; filename=timesheet.txt"
    return response



@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST" and "username" in request.form:
        username = request.form["username"]
        password = request.form["password"]
        remember = request.form.get("remember", "no") == "yes"

        user = User.check_login(username, password)
        if user == None:
            redirect(url_for('signup'))

        elif login_user(user):
            flash("Logged in!")
            return redirect(request.args.get("next") or url_for("main"))
        else:
            flash("Something went wrong.")
    else:
        flash("Something went wrong.")

    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def apilogin():

    if request.json and request.method == "POST" and "username" in request.json:
        username = request.json["username"]
        # if username in USER_NAMES:
        #     if login_user(USER_NAMES[username]):
        #         return jsonify({'sign-in': 'successful'})

    return jsonify({'sign-in': 'Unsuccessful'})


@app.route("/log", methods=["GET", "POST"])
@login_required
def log():

    if request.method == "POST" and "log" in request.form:
        # current_user.active = request.form["log"][0]
        # print(current_user.active)
        return redirect(url_for("main"))

    elif request.method == 'GET':

        print current_user.name
        # client = MongoClient()

        # collection = client.db.user_data


        # try:
        #     data = json.loads(request.data)
        #     print data
        #
        # except (ValueError, KeyError, TypeError):
        #     Not valid information, bail out and return an error
        #
        # return jsonify({'error': 'opps'})

        # collection.insert({"name": data['name'], "handle": data['handle'] })
        #
        # print collection.count()
        return redirect(url_for('main'), data=dta)

@app.route("/api/log", methods=["GET", "POST"])
@auth.login_required
def apilog():

    # Custom JSON api with web interface call for crazy measures
    # if not request.json:
    #     return jsonify({'error': 'please use json'})

    if request.method == 'POST' and "log" in request.json:

        # data = {
        #     'log': request.json['log'],
        #     'week': datetime.date.today().isocalendar()[1],
        #     'day':
        #     'user': current_user.name
        # }
        # print datetime.date.today().isocalendar()[1]
        # current_user.active = request.json["log"][0]
        # print current_user.active
        return jsonify({'user': ''})

    else:

        print current_user.username
        # client = MongoClient()

        # collection = client.db.user_data


        # try:
        #     data = json.loads(request.data)
        #     print data
        #
        # except (ValueError, KeyError, TypeError):
        #     Not valid information, bail out and return an error
        #
        # return jsonify({'error': 'opps'})

        # collection.insert({"name": data['name'], "handle": data['handle'] })
        #
        # print collection.count()

        # print datetime.date.today().isocalendar()[1]
        return jsonify({'user': current_user.username,
                        'status': current_user.weeks})

@app.route("/api/log/all", methods=["GET"])
@auth.login_required
def apilogall():

    # client = MongoClient()

    # collection = client.db.user_data


    # try:
    #     data = json.loads(request.data)
    #     print data
    #
    # except (ValueError, KeyError, TypeError):
    #     Not valid information, bail out and return an error
    #
    # return jsonify({'error': 'opps'})

    # collection.insert({"name": data['name'], "handle": data['handle'] })
    #
    # print collection.count()
    # username = request.json["username"]
    # if username in USER_NAMES:
    #     if login_user(USER_NAMES[username]):
    #         print datetime.date.today().isocalendar()[1]
    return jsonify({'user': current_user.username,
                    'weeks': data_example})

@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash(u"Reauthenticated.")
        return redirect(request.args.get("next") or url_for("index"))
    return render_template("reauth.html")

@app.route("/sign-up", methods=["GET", "POST"])
def signup():
    if request.method == "POST" and "username" in request.form:
        username = request.form["username"]
        password = request.form["password"]

        user = User.get(username)
        if user is None:
            user = User(username, password)
            user.save_user_only()
            login_user(user)
            return redirect(url_for("main"))
        else:
            flash("Username taken")
            return redirect(url_for("signup"))

    elif request.method == "GET":
        return render_template("signup.html")



@app.route("/logout")
@login_required
def logout():
    logout_user()

    flash("Logged out.")
    return redirect(url_for("index"))

def mongodb_uri():
    local = os.environ.get("MONGODB", None)
    if local:
        return local
    services = json.loads(os.environ.get("VCAP_SERVICES", "{}"))
    if services:
        creds = services['mongodb-1.8'][0]['credentials']
        uri = "mongodb://%s:%s@%s:%d/%s" % (
            creds['username'],
            creds['password'],
            creds['hostname'],
            creds['port'],
            creds['db'])
        print >> sys.stderr, uri
        return uri
    else:
        uri = "mongodb://localhost:27017"


# @app.before_first_request
# def initialize():
    # from pymongo import Connection
    # uri = mongodb_uri()
    # conn = Connection(uri)
    # collection = conn.db.user_data
    # collection.remove()

if __name__ == "__main__":
    app.run()