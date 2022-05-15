from functools import wraps
import json
from os import environ as env
from pprint import pprint

from werkzeug.exceptions import HTTPException
import secrets

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from functools import wraps
import json
from os import environ as env
from typing import Dict
from flask_cors import cross_origin

from six.moves.urllib.request import urlopen

from dotenv import load_dotenv, find_dotenv
from flask import Flask, request, jsonify, _request_ctx_stack, Response
from jose import jwt

from FlaskAuthWrapper import FlaskAuthWrapper

import requests
import constants
from FlaskAppWrapper import FlaskAppWrapper

class FlaskAppHandler:
    def __init__(self, app: Flask, auth: FlaskAuthWrapper):
        self.auth = auth
        self.app = app

        self.app.add_url_rule("/", "/", self.home)
        self.app.add_url_rule("/login", "login", self.login)
        self.app.add_url_rule("/callback_login", "callback_login", self.callback_login)
        self.app.add_url_rule("/dashboard", "dashboard", self.dashboard)
        self.app.add_url_rule("/logout", "logout", self.logout)

    # Controllers API
    def home(self):
        return redirect('/login')

    def login(self):
        return self.auth.auth0.authorize_redirect(redirect_uri=constants.AUTH0_CALLBACK_URL, audience=constants.AUTH0_AUDIENCE)

    def callback_login(self):
        auth_resp = self.auth.auth0.authorize_access_token()

        # pprint(auth_resp)
        #
        token = auth_resp["access_token"]
        pprint(token)
        unverified_claims = jwt.get_unverified_claims(auth_resp["access_token"])
        pprint(unverified_claims)
        if unverified_claims.get("scope"):
            token_scopes = unverified_claims["scope"].split()
            for token_scope in token_scopes:
                pprint(token_scope)
                # if token_scope == required_scope:
                #     return True

        resp = self.auth.auth0.get('userinfo')
        userinfo = resp.json()
        pprint(userinfo)

        session[constants.JWT_PAYLOAD] = userinfo
        session[constants.PROFILE_KEY] = {
            'user_id': userinfo['sub'],
            'name': userinfo['nickname'],
            'picture': userinfo['picture']
        }

        # headers = {
        #     'Authorization': 'Bearer ' + auth_resp["access_token"],
        #     'Content-Type': 'application/json'
        # }
        # redirect_response = app.response_class(headers=headers,
        #                                        url=url_for('dashboard', _external=True, _scheme='https'))
        # return redirect_response
        # response = redirect(url_for('dashboard', _external=True, _scheme='https'))
        # response.headers = {
        #     'Authorization': 'Bearer ' + auth_resp["access_token"],
        #     'Content-Type': 'application/json'
        # }
        # pprint(url_for('dashboard', _external=True, _scheme='https'))
        # pprint(response.headers)
        # pprint(response.json)
        # return response
        # response = app.response_class(headers=headers,
        #                              is_redirect=True,
        #                              url=url_for('dashboard', _external=True, _scheme='https'))
        # return response

        return redirect(url_for('dashboard', _external=True, _scheme='https'))

    @FlaskAuthWrapper.requires_auth_session
    def dashboard(self):
        return render_template('dashboard.html',
                               userinfo=session[constants.PROFILE_KEY],
                               userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))

    def logout(self):
        session.clear()
        params = {'returnTo': url_for('login', _external=True, _scheme='https'), 'client_id': constants.AUTH0_CLIENT_ID}
        return redirect(self.auth.auth0.api_base_url + '/v2/logout?' + urlencode(params))

