from flask import Flask, render_template, make_response
from flask_restful import Resource, Api
from flask_bootstrap import Bootstrap

application = Flask(__name__)
Bootstrap(application)
api = Api(application)

class Index(Resource):
    def get(self):
        return make_response(render_template("index.html"))

api.add_resource(Index, '/')

if __name__ == '__main__':
    application.run()