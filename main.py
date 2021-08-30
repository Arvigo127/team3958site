from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import login_required, login_user, LoginManager, logout_user, UserMixin, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import pyqrcode
import png
from pyqrcode import QRCode
import math

app = Flask(__name__)
app.config["DEBUG"] = True



#database setup/connect
SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="arvigo6015",
    password="WilsonMakesData@1",
    hostname="arvigo6015.mysql.pythonanywhere-services.com",
    databasename="arvigo6015$comment",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)




# general functions
#converts datetime time (hours and minutes) to minutes
def minutetime(time):
    total = (time.hour * 60) + time.minute
    return total

#turns minutetime format into readable one, the decorator makes it accessable in jinja
@app.template_filter('round')
def rounddowntime(time):
    hours = math.floor(time/60)
    minutes = time % 60
    timestr = str(hours) + " hours, " + str(minutes) + " minutes"
    return timestr

@app.template_filter('twelvehour')
def twelvehourtime(time):
    hours = math.floor(time/60)
    minutes = time % 60
    timeofday = "am"
    if hours > 12:
        hours -= 12
        timeofday = "pm"
    timestamp = str(hours) + ":" + str(minutes) + timeofday #who needs strftime anyways...
    return timestamp



#user data
app.secret_key = "henrysecretkey"
login_manager = LoginManager()
login_manager.init_app(app)

#fetches user instance from username
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(username=user_id).first()

#class for user data, numerous class methods for various functionalities
class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128))
    password_hash = db.Column(db.String(128))
    hours = db.Column(db.Integer)
    admin = db.Column(db.Integer)
    inshop = db.Column(db.Integer)
    whenarrived = db.Column(db.Integer)



    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


    def get_id(self):
        return self.username

    def check_admin(self):
        return (self.admin == 1)

    def elevate_admin(self):
        self.admin = 1
        db.session.commit()

    def remove_admin(self):
        self.admin=0
        db.session.commit()

    def check_in(self, time):
        self.inshop = 1
        self.whenarrived = time
        db.session.commit()

    def check_out(self, time):
        self.inshop = 0
        self.hours += time - self.whenarrived
        self.whenarrived = 0
        db.session.commit()

    def settimezero(self):
        self.hours = 0
        db.session.commit()

    def change_hours(self, target):
        self.hours = target
        db.session.commit()

    def change_password(self, pw):
        self.password_hash = pw
        db.session.commit()





#vestigial, might have use for storing data for a news section
class Comment(db.Model):

    __tablename__ = "comment"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(4096))




#home page
@app.route("/")
def index():
    total_hours = 0
    users=User.query.all()
    for i in users:
        total_hours += i.hours
    if not current_user.is_authenticated:
        return render_template("home-page.html", total_hours=total_hours)
    user=User.query.filter_by(username=current_user.username).first()
    roundedtime = rounddowntime(user.hours)
    return render_template("home-page.html", user=user, roundedtime=roundedtime, total_hours=total_hours)



#account management code
@app.route("/login/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login_page.html", error=False)

    user = load_user(request.form["username"])
    if user is None:
        return render_template("login_page.html", error=True)

    if not user.check_password(request.form["password"]):
        return render_template("login_page.html", error=True)

    login_user(user)

    return redirect(url_for('index'))

@app.route("/register/", methods=['GET', 'POST'])
def register():
    if request.method == "GET":
        return render_template("register_page.html", error=False)

    username = request.form['username']
    password = request.form['password']

    if username is None:
        return render_template("register_page.html", error=True)

    if password is None:
        return render_template("register_page.html", error=True)

    if load_user(username) is not None:
        return render_template("register_page.html", error=True)

    user = User(username=username, password_hash=generate_password_hash(password), admin=0, hours=0, inshop=0, whenarrived=0)
    db.session.add(user)
    db.session.commit()

    return redirect(url_for("login"))


#logs a user out
@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

#separate login function which goes through qr code link, in future could be combined with main login function
#would need to be able to redirect to give login function a link to redirect to after
@app.route("/<requested>/qrlogin/", methods=['GET', 'POST'])
def qrlogin(requested):
    if request.method == "GET":
        return render_template("qrlogin.html", error=False)

    user = load_user(request.form["username"])
    if user is None:
        return render_template("login_page.html", error=True)

    if not user.check_password(request.form["password"]):
        return render_template("login_page.html", error=True)

    login_user(user)

    return redirect(url_for('checkin', username=user.username))

@app.route("/changepassword/<username>/", methods = ["GET", "POST"])
@login_required
def changepassword(username):
    if not current_user.check_admin:
        return redirect(url_for('index'))
    if request.method == "GET":
        return render_template('changepassword.html', error=False)

    user = load_user(username)

    if user is None:
        return render_template('changepassword.html', error=True)


    password = generate_password_hash(request.form['password'])

    user.change_password(password)

    return redirect(url_for('admin'))







#administrative code
@app.route("/admin/")
@login_required
def admin():
    if not current_user.check_admin():
        return redirect(url_for('index'))
    return render_template('admin-controls.html', users=User.query.all())


#generates login qr code based off administrator's username
@app.route("/<requested>/qrcode/")
@login_required
def qrcode(requested):
    link = "https://arvigo6015.pythonanywhere.com/" + url_for('qrlogin', requested=requested)
    url = pyqrcode.create(link)
    destination = "/home/arvigo6015/mysite/static/" + requested + "qrcode.png"
    filename = requested+"qrcode.png"
    url.png(destination, scale = 6)

    return render_template("qrcode.html", link=filename)


#promotes a user to admin
@app.route("/elevate/<user>")
@login_required
def elevate(user):
    if not current_user.check_admin():
        return redirect(url_for('index'))
    newadmin = load_user(user)
    newadmin.elevate_admin()
    return redirect(url_for('admin'))


#demotes a user from admin
@app.route("/demote/<user>")
@login_required
def demote(user):
    if not current_user.check_admin():
        return redirect(url_for('index'))
    oldadmin = load_user(user)
    oldadmin.remove_admin()
    return redirect(url_for('admin'))


#checks a user in, using current time
@app.route("/<username>/checkin/")
@login_required
def checkin(username):
    if username == current_user.username or current_user.check_admin:
        user = load_user(username)
        if user.inshop == 1:
            return redirect(url_for('index'))
        now = datetime.datetime.now()
        minutenow = minutetime(now)
        user.check_in(minutenow)
        if current_user.check_admin:
            return redirect(url_for('admin'))

        return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))


#checks a user out, verifying they're the right one or an admin, subtracts current time from checkin time
@app.route("/<username>/checkout/")
@login_required
def checkout(username):
    if username == current_user.username or current_user.check_admin:

        user = load_user(username)
        if user.inshop == 0:
            return redirect(url_for('index'))
        now = datetime.datetime.now()
        minutenow = minutetime(now)
        user.check_out(minutenow)
        if current_user.check_admin:
            return redirect(url_for('admin'))

        return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))


#queries all checked in users, calls checkout function on them, verifies an admin is doing it
@app.route("/checkallout/")
@login_required
def checkallout():
    if not current_user.check_admin:
        return redirect(url_for('index'))
    logged_in_users = User.query.filter_by(inshop=1).all()
    for user in logged_in_users:
        now = datetime.datetime.now()
        minutenow = minutetime(now)
        user.check_out(minutenow)
    return redirect(url_for('admin'))


#changes a user's hours, verifies an admin
@app.route("/<username>/changehours/", methods=['GET', 'POST'])
@login_required
def changehours(username):
    if not current_user.check_admin:
        return redirect(url_for('index'))
    if request.method == 'GET':
        return render_template("changehours.html", error=False)

    user = load_user(username)
    th = int(request.form['targethours'])
    tm = int(request.form['targetminutes'])
    total_target = (th*60)+tm

    user.change_hours(total_target)

    return redirect(url_for('admin'))


#deletes an account of the given username
@app.route("/<username>/delete/")
@login_required
def delete(username):
    if not current_user.check_admin:
        return redirect(url_for('index'))
    user = load_user(username)
    if username == current_user.username:
        return redirect(url_for('admin'))

    db.session.delete(user)
    db.session.commit()

    return redirect(url_for('admin'))


#just a confirm page for the wipe data admin function
@app.route("/confirm/")
@login_required
def confirm():
    return render_template("confirm.html")


#deletes every account except administrators
@app.route('/nuclearoption/')
@login_required
def nuclearoption():
    if not current_user.check_admin:
        return redirect(url_for('index'))
    users=User.query.all()
    for i in users:
        if i.admin == 0:
            db.session.delete(i)

    db.session.commit()
    return redirect(url_for('admin'))
