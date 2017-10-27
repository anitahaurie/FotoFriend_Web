import flask
import httplib2
import uuid
import http.client
import os
from werkzeug.utils import secure_filename

from flask_restful import Resource, Api
from flask_bootstrap import Bootstrap
from apiclient import discovery
from oauth2client import client

UPLOAD_FOLDER = '' #Location depends where the photos will stored
                    #May be on EC2 Server instance
ALLOWED_EXTENSIONS = set(['jpeg', 'jpg', 'png'])

application = flask.Flask(__name__)
application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
Bootstrap(application)
api = Api(application)
application.secret_key = str(uuid.uuid4())

# For cloud server
http_server = "fotofriendserver.us-west-2.elasticbeanstalk.com"

def authenticate():
    #If no credentials, prompt for info
    if 'credentials' not in flask.session:
        return flask.make_response(flask.render_template("index.html"))
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    #If credentials are expired, prompt for info
    if credentials.access_token_expired:
        return flask.make_response(flask.render_template("index.html"))
    return flask.redirect(flask.url_for('home'))

class Index(Resource):
    def get(self):
        return authenticate()

class oAuth(Resource):
    def get(self):
      flow = client.flow_from_clientsecrets(
          'client_secret.json',
          scope='https://www.googleapis.com/auth/drive',
          redirect_uri=flask.url_for('oauth', _external=True))

      if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
      else:
        auth_code = flask.request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        flask.session['credentials'] = credentials.to_json()
        return flask.redirect(flask.url_for('index'))

class LogOut(Resource):
    def get(self):
        if 'credentials' in flask.session:
            del flask.session['credentials']

        return flask.redirect(flask.url_for('index'))

class Home(Resource):
    def get(self):
        authenticate()

        credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])

        http_auth = credentials.authorize(httplib2.Http())
        drive = discovery.build('drive', 'v2', http_auth)
        about = drive.about().get().execute()
        user = about['user']['emailAddress']

        # Connect HTTP
        conn = http.client.HTTPConnection(http_server)

        # Make request
        conn.request("GET", "/")

        # Get response
        try:
            response = conn.getresponse()
            response = response.read()
        except:
            response = ""

        # Close connection
        conn.close()

        return flask.make_response(flask.render_template("home.html", userEmail=user, serverResponse=response))

class Search(Resource):
    def get(self):
        keywords = flask.request.args.getlist("keyword")

        tag_list = []
        for keyword in keywords:
            tag_list.append(keyword)

        return flask.render_template('tags.html', tags=tag_list)

#Check whether the filename extension is allowed 
def checkFileExtension(filename):
    return '.' in filename and 
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Upload(Resource):
    def get(self):
        if request.method == 'POST':
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']


api.add_resource(Index, '/')
api.add_resource(oAuth, '/oAuth')
api.add_resource(LogOut, '/logout')
api.add_resource(Home, '/home')
api.add_resource(Search, '/search')
api.add_resource(Upload, '/upload')

if __name__ == '__main__':
    application.debug = False
    application.run()