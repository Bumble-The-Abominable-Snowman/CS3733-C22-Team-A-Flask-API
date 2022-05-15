from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException
from functools import wraps
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for

import flask
import constants

class FlaskAppWrapper(object):

    def __init__(self, import_name: str ):
        self.app = Flask(import_name, static_url_path='/public', static_folder='./public')
        self.app.secret_key = constants.SECRET_KEY
        self.app.debug = True

    def add_endpoint(self, endpoint: str = None, endpoint_name: str = None, handler=None, methods=None, *args, **kwargs):
        if endpoint_name is None:
            endpoint_name = endpoint.lstrip("/")

        if methods is None:
            methods = ['GET', 'POST']

        self.app.add_url_rule(endpoint, endpoint_name, handler, methods=methods, *args, **kwargs)
