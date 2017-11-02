import flask
import httplib2
import uuid
import requests
import os
import json

from flask_restful import Resource, Api
from flask_bootstrap import Bootstrap
from apiclient import discovery
from oauth2client import client

#UPLOAD_FOLDER ='C:\\Users\\thoma\\Documents' #Test
UPLOAD_FOLDER = '' #Location depends where the photos will stored
ALLOWED_EXTENSIONS = set(['jpeg', 'jpg', 'png'])

application = flask.Flask(__name__)
application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
Bootstrap(application)
api = Api(application)
application.secret_key = str(uuid.uuid4())

# For cloud server
http_server = "fotofriendserver.us-west-2.elasticbeanstalk.com"

#For local server (Testing)
#http_server = "127.0.0.1:80"

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

        # Connect to the user's MongoDB collection
        headers = {'Content-Type': 'application/json'}
        data = json.dumps({'username': user})
        response = requests.post("http://%s/login" % http_server, data = data, headers = headers)

        links = response.json()

        return flask.make_response(flask.render_template("home.html", userEmail=user, linkList=links['Links']))

class Search(Resource):
    def get(self):
        keywords = flask.request.args.getlist("keyword")

        tag_list = []
        for keyword in keywords:
            tag_list.append(keyword)

        headers = {'Content-Type': 'application/json'}
        data = json.dumps({'keywords': tag_list, 'username': flask.session['username']})
        response = requests.post("http://%s/filter" % http_server, data = data, headers = headers)
        links = response.json()

        return flask.render_template('tags.html', tags=tag_list, linkList=links['Links'])

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
        if file and checkFileExtension(file.filename):
            #Send file to Backend Server
            file.save(os.path.join(application.config['UPLOAD_FOLDER'], file.filename))

            response = requests.post("http://%s/storeImage" % http_server, files={'file': open(os.path.join(application.config['UPLOAD_FOLDER'], file.filename), 'rb'), 'username': flask.session['username']})

            os.remove(os.path.join(application.config['UPLOAD_FOLDER'], file.filename))

            if response.status_code == 200:
                flask.flash("Your upload was successful!")

            return flask.redirect(flask.url_for('home'))
        else:
            flask.flash("Only jpeg, jpg and png files are supported. Please try again.")
            return flask.redirect(flask.url_for('home'))

api.add_resource(Index, '/')
api.add_resource(oAuth, '/oAuth')
api.add_resource(LogOut, '/logout')
api.add_resource(Home, '/home')
api.add_resource(Search, '/search')
api.add_resource(Upload, '/upload')

if __name__ == '__main__':
    application.debug = False
    application.run()