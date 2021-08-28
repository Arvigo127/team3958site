from flask import Flask

app = Flask(__name__)

import home
app.register_blueprint(home.bp)
app.add_url_rule('/', endpoint='index')