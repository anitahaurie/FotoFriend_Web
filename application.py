import flask
import httplib2
import uuid

from flask_restful import Resource, Api
from flask_bootstrap import Bootstrap

from apiclient import discovery
from oauth2client import client

application = flask.Flask(__name__)
Bootstrap(application)
api = Api(application)

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

class Home(Resource):
    def get(self):
        authenticate()

        credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])

        http_auth = credentials.authorize(httplib2.Http())
        drive = discovery.build('drive', 'v2', http_auth)
        about = drive.about().get().execute()
        user = about['user']['emailAddress']

        return flask.make_response(flask.render_template("home.html", userEmail=user))

api.add_resource(Index, '/')
api.add_resource(oAuth, '/oAuth')
api.add_resource(Home, '/Home')

if __name__ == '__main__':
    application.secret_key = str(uuid.uuid4())
    application.debug = False
    application.run()