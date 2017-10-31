import flask
import httplib2
import uuid
import http.client
import os
import requests

from flask_restful import Resource, Api
from flask_bootstrap import Bootstrap
from apiclient import discovery
from oauth2client import client
from flask import send_from_directory, request, flash, redirect
from werkzeug.utils import secure_filename

#UPLOAD_FOLDER ='C:\\Users\\David\\Desktop\\Photos' #Test
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
    return flask.redirect(flask.url_for('home'))

#Check whether the filename extension is allowed 
def checkFileExtension(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


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
            response = response.read().decode()
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

class Upload(Resource):
	def post(self):
		#Check if POST request has it's File component
		#NOTE: The flash message should be embedded within the home html file to display status to user
		if 'file' not in  request.files:
			print('No file part')
			flash('No file part')
			return redirect(request.url)

		else:
			file = request.files['file']

		#Check whether a file was selected
		if file.filename == '':
			print("No file was selected. Please try again")
			flash("No file was selected. Please try again")
			return redirect(flask.url_for('home'))
		
		#Add the picture to the path where pictures will be stored
		if file and checkFileExtension(file.filename):
			#Returns a secure version of the filename
			filename = secure_filename(file.filename)

			#Send file to Backend Server
			conn = http.client.HTTPConnection(http_server)

			conn.request('POST', '/storeImage', file)

			try:
				response = conn.getresponse()
			except:
				response = "Something went wrong."

			conn.close()

			if response.status == 200:
				flash((response.read()).decode())

			return redirect(flask.url_for('home'))
		else:
			flash("Only jpeg, jpg and png files are supported. Please try again.")
			return redirect(flask.url_for('home'))


api.add_resource(Index, '/')
api.add_resource(oAuth, '/oAuth')
api.add_resource(LogOut, '/logout')
api.add_resource(Home, '/home')
api.add_resource(Search, '/search')
api.add_resource(Upload, '/upload')

if __name__ == '__main__':
    application.debug = False
    application.run()