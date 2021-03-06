import datetime
import json
import os
from pymongo import Connection
# from bson import json_util
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, make_response, Response, abort
from flask.ext.login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin
from flask.ext.httpauth import HTTPBasicAuth
import sys
from dateutil import parser



class User(UserMixin):

    def __init__(self, username, password, weeks=[]):
        self.username = username
        self.password = password
        self.weeks = weeks
        self.todayarr = []
        # day needs to be consistent with java/JS

    def get_id(self):
        return unicode(str(self.username))

    def get_weeks(self):
        return self.weeks

    def _get_time_arr(self):
        collection = User._getcol()
        dt = collection.find({"name": self.username}, {'_id': 0}).limit(1)[0]
        return dt["weeks"]

    def get_all_checkins(self):
        return self._get_time_arr()

    def save_user_only(self):
        collection = User._getcol()
        collection.insert({'name': self.username,
                           'password': self.password,
                           'checked-in': 'false',
                           'files': [],
                           'weeks': []})

    def is_checked_in(self):
        collection = User._getcol()
        finding = collection.find({'name': self.username}).limit(1)[0]

        if "true" in finding["checked-in"]:
            return {"checked-in": "true", "time-in": finding["in"]}
        else:
            return {"checked-in": "false"}

    def log(self, time):
        collection = User._getcol()
        finding = collection.find({'name': self.username}).limit(1)[0]
        parsed_time = parser.parse(str(time))

        if finding["checked-in"] == 'true':
            cin = finding["in"]
            totarr = finding["weeks"]
            totarr.append({'week': parsed_time.isocalendar()[1],
                           'in': cin, 'out': str(parsed_time),
                           'day': parsed_time.isocalendar()[2]})

            collection.update({'name': self.username}, {'$set': {'checked-in': 'false', 'weeks': totarr}})

        else:
            collection.update({'name': self.username}, {'$set': {'checked-in': 'true', 'in': str(parsed_time)}})

    def today(self):
        _week = datetime.date.today().isocalendar()[1]
        _day = datetime.date.today().isocalendar()[2]

        collection = User._getcol()
        dt = collection.find({"name": self.username}, {'_id': 0}).limit(1)[0]
        # print f
        arr = []
        for x in dt["weeks"]:
            if x['week'] == _week and x['day'] == _day:
                arr.append(x)
        return arr


    def get_week(self, week):

        collection = User._getcol()
        dt = collection.find({"name": self.username}, {'_id': 0}).limit(1)[0]
        # print f
        arr = []
        for x in dt["weeks"]:
            if x['week'] == week:
                arr.append(x)
        print arr
        return arr

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

        if finding is not None:
            # print finding
            return User(finding["name"], finding["password"], finding["weeks"])
        else:
            return None

    @staticmethod
    def check_login(username, password):
        collection = User._getcol()
        finding = collection.find_one({'name': username, 'password': password})

        if finding is not None:
            # print finding
            return User(finding["name"], finding["password"], finding["weeks"])
        else:
            return None

    @staticmethod
    def get_password(username):
        collection = User._getcol()
        finding = collection.find_one({'name': username})
        if finding is not None:
            # print finding
            return finding["password"]
        else:
            return None


ALLOWED_EXTENSIONS = set(['pdf'])

application = app = Flask(__name__)

SECRET_KEY = "KJ&DKJEu*&he58*9fhsHh9f8y8"

app.debug = True

app.config.from_object(__name__)

auth = HTTPBasicAuth()
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"


@auth.get_password
def get_password(name):
    pswd = User.get_password(name)
    if pswd is not None:
        user = User.check_login(name, pswd)
        if user is not None:
            login_user(user)
            return pswd
    return None

# @auth.verify_password(password)


@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)


@login_manager.user_loader
def load_user(username):

    return User.get(username)


@app.route("/")
def index():
    if current_user.is_anonymous():
        return render_template("index.html")
    else:
        return redirect(url_for('main'))


@app.route("/main")
@login_required
def main():
    weeknum = datetime.date.today().isocalendar()[1]
    s = current_user.today()
    c = json.dumps(current_user.get_week(weeknum))
    return render_template("main.html", data=s, fdata=c)




@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST" and "username" in request.form:
        username = request.form["username"]
        password = request.form["password"]
        #remember = request.form.get("remember", "no") == "yes"

        user = User.check_login(username, password)
        if user is None:
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
@auth.login_required
def api_login():

    if not current_user.is_anonymous():
        return Response(response=json.dumps({'status': 'Successful'}),
                        status=200,
                        headers=None,
                        content_type='application/json',
                        direct_passthrough=False)


@app.route("/log", methods=["POST"])
@login_required
def log():
    # print "form sent", request.form["log"]
    data = request.form["time"]

    current_user.log(data)
    # print current_user.in_out
    return redirect(url_for("main"))


@app.route("/api/log", methods=["POST"])
@auth.login_required
def api_log():

    if not current_user.is_anonymous():
        data = json.loads(request.data)

        current_user.log(data['time'])
        return Response(response=json.dumps(current_user.is_checked_in()),
                        status=200,
                        headers=None,
                        content_type='application/json',
                        direct_passthrough=False)


@app.route("/api/log/status", methods=["GET"])
@auth.login_required
def api_log_status():

    if not current_user.is_anonymous():
        return Response(response=json.dumps(current_user.is_checked_in()),
                        status=200,
                        headers=None,
                        content_type='application/json',
                        direct_passthrough=False)


@app.route("/api/log/today", methods=["GET"])
@auth.login_required
def api_log_today():
        s = current_user.today()
        return jsonify({'user': current_user.username,
                        'check-ins': s})


@app.route("/api/log/all", methods=["GET"])
@auth.login_required
def api_log_all():

    return jsonify({'user': current_user.username,
                    'check-ins': current_user.get_all_checkins()})


@app.route("/api/log/<int:wk>", methods=["GET"])
@auth.login_required
def api_get_specific(wk):

    return jsonify({'user': current_user.username,
                    'check-ins': current_user.get_week(wk)})


# @app.route("/reauth", methods=["GET", "POST"])
# @login_required
# def reauth():
#     if request.method == "POST":
#         confirm_login()
#         flash(u"Reauthenticated.")
#         return redirect(request.args.get("next") or url_for("index"))
#     return render_template("reauth.html")


@app.route("/sign-up", methods=["GET", "POST"])
def signup():
    if request.method == "POST" and "username" in request.form:
        code = request.form["code"]

        if code == "imin":

            username = request.form["username"]
            password = request.form["password"]

            user = User.get(username)
            if user is None:
                user = User(username, password, [])
                user.save_user_only()
                login_user(user)
                return redirect(url_for("main"))
            else:
                flash("Username taken")
                return redirect(url_for("signup"))
        else:
            flash("Sorry, code is invalid")
            return render_template("signup.html")

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
#     from pymongo import Connection
#     uri = mongodb_uri()
#     conn = Connection(uri)
#     collection = conn.db.user_data
#     collection.remove()

if __name__ == "__main__":
    app.run()