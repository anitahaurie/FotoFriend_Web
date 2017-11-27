import flask
import httplib2
import uuid
import requests
import os
import json
import base64

from flask_restful import Resource, Api
from flask_bootstrap import Bootstrap
from apiclient import discovery
from oauth2client import client

import fotofriend

#UPLOAD_FOLDER ='C:\\Users\\thoma\\Documents' #Test
UPLOAD_FOLDER = '' #Location depends where the photos will stored
ALLOWED_EXTENSIONS = set(['jpeg', 'jpg', 'png'])
DEV = "FOTOFRIEND_DEV"

application = flask.Flask(__name__)
application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
Bootstrap(application)
api = Api(application)
application.secret_key = str(uuid.uuid4())

#For local server (Testing)
HTTP_SERVER = "127.0.0.1:80"

def authenticate():
    #If no credentials, prompt for info
    if 'credentials' not in flask.session:
        return flask.make_response(flask.render_template("index.html"))
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    #If credentials are expired, prompt for info
    if credentials.access_token_expired:
        return flask.make_response(flask.render_template("index.html"))

    # Save username in session
    http_auth = credentials.authorize(httplib2.Http())
    drive = discovery.build('drive', 'v2', http_auth)
    about = drive.about().get().execute()
    user = about['user']['emailAddress']
    user = user.replace('@gmail.com', '')
    flask.session['username'] = user

    return flask.redirect(flask.url_for('home'))

#Check whether the filename extension is allowed 
def checkFileExtension(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def uploaded_file(filename):
    return flask.send_from_directory(app.config['UPLOAD_FOLDER'], filename)

class Index(Resource):
    def get(self):
        return authenticate()

class oAuth(Resource):
    def get(self):
      flow = client.flow_from_clientsecrets(
          'client_secret.json',
          scope = 'https://www.googleapis.com/auth/drive',
          redirect_uri = flask.url_for('oauth', _external=True))

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
        user = flask.session['username']

        links = []

        # FOR DEVELOPMENT
        if DEV in os.environ:
            headers = {'Content-Type': 'application/json'}
            data = json.dumps({'username': user})
            response = requests.post("http://%s/login" % HTTP_SERVER, data = data, headers = headers)
            links = response.json()
        else:
            links = fotofriend.login(user)

        return flask.make_response(flask.render_template("home.html", userEmail=user, linkList=links['Links']))

class Search(Resource):
    def get(self):
        keywords = flask.request.args.getlist("keyword")

        links = []
        user = flask.session['username']

        if DEV in os.environ:
            headers = {'Content-Type': 'application/json'}
            data = json.dumps({'keywords': keywords, 'username': user})
            response = requests.post("http://%s/filter" % HTTP_SERVER, data = data, headers = headers)
            links = response.json()
        else:
            links = fotofriend.filter(keywords, user)

        return flask.render_template('tags.html', tags=keywords, linkList=links['Links'])

class Upload(Resource):
    def post(self):
        #Check if POST request has it's File component
        #NOTE: The flash message should be embedded within the home html file to display status to user
        if 'file' not in flask.request.files:
            flask.flash('No file part')
            return flask.redirect(flask.request.url)
        else:
            file = flask.request.files['file']

        #Check whether a file was selected
        if file.filename == '':
            flask.flash("No file was selected. Please try again")
            return flask.redirect(flask.url_for('home'))

        #Add the picture to the path where pictures will be stored
        #Send file to Backend Server
        file.save(os.path.join(application.config['UPLOAD_FOLDER'], file.filename))
        image = open(os.path.join(application.config['UPLOAD_FOLDER'], file.filename), 'rb').read()

        message = None
        user = flask.session['username']

        if DEV in os.environ:
            response = requests.post("http://%s/storeImage" % HTTP_SERVER, data=dict(file=base64.b64encode(image), filename=file.filename, username=user))

            if response.status_code == 200:
                message = "Your upload was successful!"
            else:
                message = "Only jpeg, jpg and png files are supported. Please try again."
        else:
            code = fotofriend.uploadImage(image, file.filename, user)
            if code == 1:
                message = "Your upload was successful!"
            else:
                message = "Only jpeg, jpg and png files are supported. Please try again."

        os.remove(os.path.join(application.config['UPLOAD_FOLDER'], file.filename))

        flask.flash(message)
        return flask.redirect(flask.url_for('home'))

class Delete(Resource):
    def get(self):
        url = flask.request.args.get("url")
        user = flask.session['username']

        message = None
        if DEV in os.environ:
            headers = {'Content-Type': 'application/json'}
            data = json.dumps({'url': url, 'username': user})
            response = requests.post("http://%s/deleteImage" % HTTP_SERVER, data = data, headers = headers)

            if response.status_code == 200:
                message = "Your delete was successful!"
        else:
            code = fotofriend.deleteImage(url, user)
            if code == 200:
                message = "Your delete was successful!"

        flask.flash(message)
        return 200

api.add_resource(Index, '/')
api.add_resource(oAuth, '/oAuth')
api.add_resource(LogOut, '/logout')
api.add_resource(Home, '/home')
api.add_resource(Search, '/search')
api.add_resource(Upload, '/upload')
api.add_resource(Delete, '/delete')

if __name__ == '__main__':
    application.debug = False
    application.run()