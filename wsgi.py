import datetime
import json
import os
from pymongo import Connection
# from bson import json_util
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, make_response, Response, abort, Request
from flask.ext.login import LoginManager, current_user, login_required, login_user, logout_user, UserMixin, confirm_login
from flask.ext.httpauth import HTTPBasicAuth
import sys
from dateutil import parser
from gridfs import GridFS
from gridfs.errors import NoFile


class User(UserMixin):

    def __init__(self, username, password, weeks=[], in_out={"in": "", "out": ""}):
        self.username = username
        self.password = password
        self.weeks = weeks
        self.todayarr = []



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
        weeknum = datetime.date.today().isocalendar()[1]
        day = datetime.date.today().weekday()
        timeGiven = parser.parse(str(time))

        if finding["checked-in"] == 'true':

            cin = finding["in"]
            totarr = finding["weeks"]
            totarr.append({'week': weeknum, 'in': '2014-01-8 12:00:31-07:00', 'out': '2014-01-8 17:03:31-07:00', 'day': 3})
            collection.update({'name': self.username}, {'$set': {'checked-in': 'false', 'weeks': totarr}})

        else:
            timeGiven = parser.parse(str(time))
            collection.update({'name': self.username}, {'$set': {'checked-in': 'true', 'in': str(timeGiven)}})


    def today(self):
        weeknum = datetime.date.today().isocalendar()[1]
        day = datetime.date.today().weekday()
        collection = User._getcol()
        dt = collection.find({"name": self.username}, {'_id': 0}).limit(1)[0]
        # print f
        arr = []
        for x in dt["weeks"]:
            if x['week'] == weeknum and x['day'] == day:
                arr.append(x)
        return arr

    def add_file(self, fname):
        collection = User._getcol()
        finding = collection.find({'name': self.username}).limit(1)[0]
        filesarr = finding["files"]
        print filesarr
        filesarr = [fname]
        collection.update({'name': self.username}, {'$set': {'files': fname}})

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

    # def update_times(self):
    #     collection = User._getcol()
    #     finding = collection.find_one({'name': self.username})
    #     weeknum = datetime.date.today().isocalendar()[1]


    @staticmethod
    def _getcol():
        uri = mongodb_uri()
        conn = Connection(uri)
        collection = conn.db.user_data
        return collection

    @staticmethod
    def get_grid():
        uri = mongodb_uri()
        conn = Connection(uri)
        DB = conn.db
        return GridFS(DB)

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


ALLOWED_EXTENSIONS = set(['pdf'])

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
    if current_user.is_anonymous():
        return render_template("index.html")
    else:
        return render_template("main.html")

@app.route("/main")
@login_required
def main():
    weeknum = datetime.date.today().isocalendar()[1]
    s = current_user.today()
    c = json.dumps(current_user.get_week(weeknum))
    return render_template("main.html", data=s, fdata=c)

@app.route("/upload", methods=["POST", "GET"])
@login_required
def upload_file():

    if request.method == 'POST':
        # TODO check file
        file = request.files['file']
        userFN = request.form['filename']
        filename = file.filename
        fs = User.get_grid()
        oid = fs.put(file, content_type=file.content_type, filename=filename)
        current_user.add_file(str(oid))
        return redirect(url_for('main', oid=str(oid)))

    elif request.method == "GET":
        return render_template("uploadts.html")

@app.route("/download", methods=["GET"])
@login_required
def download_file():
    FS = User.get_grid()

    files = [FS.get_last_version(file) for file in FS.list()]
    file_list = ['http://timetracker.aws.af.cm%s' % (url_for('serve_gridfs_file_by_name', filename=str(file.name))) for file in files]
    file_list = "\n".join(['<li><a href="%s">%s</a></li>' % \
                           (url_for('serve_gridfs_file_by_name', filename=str(file.name)), file.name) \
                           for file in files])
    print file_list


    return file_list

# get file by filename
@app.route('/<filename>')
def serve_gridfs_file_by_name(filename):
    FS = User.get_grid()
    try:
        file = FS.get_last_version(filename)
        response = make_response(file.read())
        response.mimetype = file.content_type
        return response
    except NoFile:
        abort(404)

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
            return redirect(request.args.get("next") or url_for("index"))
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
                    'weeks': current_user.get_all_checkins()})

@app.route("/api/log/<int:wk>", methods=["GET"])
@auth.login_required
def api_get_specific(wk):

    return jsonify({'user': current_user.username,
                    'weeks': current_user.get_week(wk)})

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