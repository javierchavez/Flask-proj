import datetime
import json
import os
from pymongo import Connection
from bson import json_util
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, make_response, Response
import time
from flask.ext.login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin, confirm_login
from flask.ext.httpauth import HTTPBasicAuth
import sys


class User(UserMixin):

    def __init__(self, username, password, weeks=[], in_out={"in": "", "out": ""}):
        self.username = username
        self.password = password
        self.weeks = weeks
        self.todayarr = []

    # @property
    # def inout(self):
    #

    def get_id(self):
        return unicode(str(self.username))

    def get_weeks(self):
        return self.weeks

    def _get_time_arr(self):
        dayofweek = datetime.datetime.today().weekday()
        weeknum = datetime.date.today().isocalendar()[1]
        collection = User._getcol()
        dt = collection.find({'name':self.username}, {'weeks.week':weeknum}).limit(1)[0]
        print "====>",dt


    def get_curr_checkins(self):
        return self._get_time_arr()



    def save_user_only(self):
        collection = User._getcol()
        weeknum = datetime.date.today().isocalendar()[1]
        collection.insert({'name': self.username,
                           'password': self.password,
                           'checked-in': 'false',
                           'today': [],
                           'weeks': [{'week': weeknum, "days": []}]})

    def is_checked_in(self):
        collection = User._getcol()
        finding = collection.find({'name': self.username}).limit(1)[0]
        return finding["checked-in"]

    def log(self):
        collection = User._getcol()
        finding = collection.find({'name': self.username}).limit(1)[0]
        weeknum = datetime.date.today().isocalendar()[1]

        if finding["checked-in"] == 'true':

            collection.update({'name': self.username}, {'$set': {'checked-in':'false'}})
            # collection.update({'name': self.username}, {'$set': {'in': ''}} )
            cin = finding["in"]
            arr = finding["today"]
            arr.append({'in': cin})
            arr.append({'out': time.strftime("%H:%M:%S") })
            collection.update({'name': self.username}, {'$set': {'today': arr}} )

        else:
            collection.update({'name': self.username}, {'$set': {'checked-in':'true'}} )
            collection.update({'name': self.username}, {'$set': {'in': time.strftime("%H:%M:%S")}} )

            # check to see if week is in DB if not add it

    def today(self):
        col = User._getcol()
        f = col.find({'name': self.username}).limit(1)[0]
        print f
        return f["today"]

    def update_times(self):
        collection = User._getcol()
        finding = collection.find_one({'name': self.username})
        weeknum = datetime.date.today().isocalendar()[1]


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
            return User(finding["name"], finding["password"], finding["weeks"], finding["checked-in"])
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

data_example = [{"week": 1, "days": [{"day": 1, "times": [{"in": "", "out": ""}]}]},
                {"week": 2, "days": [{"day": 6, "times": [{"in": "", "out": ""}]}]},
                {"week": 3, "days": [{"day": 3, "times": [{"in": "", "out": ""}]}]}]


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
    print current_user.is_checked_in()
    s = current_user.today()
    current_user._get_time_arr()
    return render_template("main.html", data=s)

@app.route("/upload", methods=["POST", "GET"])
@login_required
def upload_file():

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
def download_file():

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

    current_user.log()
    # print current_user.in_out
    return redirect(url_for("main"))


@app.route("/api/log", methods=["POST"])
@auth.login_required
def api_log():

    if not current_user.is_anonymous():
        current_user.log()
        return Response(response=json.dumps({'status': 'Successful', 'checked-in': current_user.is_checked_in()}),
                        status=200,
                        headers=None,
                        content_type='application/json',
                        direct_passthrough=False)

@app.route("/api/log/status", methods=["GET"])
@auth.login_required
def api_log_status():

    if not current_user.is_anonymous():
        return Response(response=json.dumps({'checked-in': current_user.is_checked_in()}),
                        status=200,
                        headers=None,
                        content_type='application/json',
                        direct_passthrough=False)

@app.route("/api/log/today", methods=["GET"])
@auth.login_required
def api_log_today():

    # Custom JSON api with web interface call for crazy measures
    # if not request.json:
    #     return jsonify({'error': 'please use json'})



        # data = {
        #     'log': request.json['log'],
        #     'week': datetime.date.today().isocalendar()[1],
        #     'day':
        #     'user': current_user.name
        # }
        # print datetime.date.today().isocalendar()[1]
        # current_user.active = request.json["log"][0]
        # print current_user.active
        s = current_user.today()
        return jsonify({'user': current_user.username,
                        'check-ins': s})

@app.route("/api/log/all", methods=["GET"])
@auth.login_required
def api_log_all():

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
            user = User(username, password, 'false')
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
#     from pymongo import Connection
#     uri = mongodb_uri()
#     conn = Connection(uri)
#     collection = conn.db.user_data
#     collection.remove()

if __name__ == "__main__":
    app.run()