from authlib.integrations.flask_client import OAuth
import constants
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

import requests
import constants


AUTH0_CALLBACK_URL = constants.AUTH0_CALLBACK_URL
AUTH0_CLIENT_ID = constants.AUTH0_CLIENT_ID
AUTH0_CLIENT_SECRET = constants.AUTH0_CLIENT_SECRET
AUTH0_DOMAIN = constants.AUTH0_DOMAIN
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = constants.AUTH0_AUDIENCE
ALGORITHMS = ["RS256"]


class AuthError(Exception):
    """
    An AuthError is raised whenever the authentication failed.
    """

    def __init__(self, error: Dict[str, str], status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


class FlaskAuthWrapper:
    def __init__(self, app):
        self.app = app
        self.oauth = OAuth(app)

        self.auth0: OAuth = self.oauth.register(
            'auth0',
            client_id=constants.AUTH0_CLIENT_ID,
            client_secret=constants.AUTH0_CLIENT_SECRET,
            api_base_url='https://' + AUTH0_DOMAIN,
            access_token_url='https://' + AUTH0_DOMAIN + '/oauth/token',
            authorize_url='https://' + AUTH0_DOMAIN + '/authorize',
            client_kwargs={
                'scope': 'openid profile email',
            },
            grant_tpe="client_credentials",
        )

    @staticmethod
    def requires_auth_session(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if constants.PROFILE_KEY not in session:
                return redirect('/login')
            return f(*args, **kwargs)

        return decorated

    @staticmethod
    def get_token_auth_header() -> str:
        """Obtains the access token from the Authorization Header
        """
        auth = request.headers.get("Authorization", None)
        if not auth:
            raise AuthError({"code": "authorization_header_missing",
                             "description":
                                 "Authorization header is expected"}, 401)

        parts = auth.split()

        if parts[0].lower() != "bearer":
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Authorization header must start with"
                                 " Bearer"}, 401)
        if len(parts) == 1:
            raise AuthError({"code": "invalid_header",
                             "description": "Token not found"}, 401)
        if len(parts) > 2:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Authorization header must be"
                                 " Bearer token"}, 401)

        token = parts[1]
        return token

    @staticmethod
    def requires_scope(required_scope: str) -> bool:
        """Determines if the required scope is present in the access token
        Args:
            required_scope (str): The scope required to access the resource
        """
        token = FlaskAuthWrapper.get_token_auth_header()
        unverified_claims = jwt.get_unverified_claims(token)
        if unverified_claims.get("scope"):
            token_scopes = unverified_claims["scope"].split()
            for token_scope in token_scopes:
                print(token_scope)
                if token_scope == required_scope:
                    return True
        return False

    @staticmethod
    def requires_permission(required_permission: str) -> bool:
        """Determines if the required scope is present in the access token
        Args:
            required_permission (str): The scope required to access the resource
        """
        token = FlaskAuthWrapper.get_token_auth_header()
        unverified_claims = jwt.get_unverified_claims(token)
        if unverified_claims.get("permissions"):
            token_permissions = unverified_claims["permissions"]
            for token_permission in token_permissions:
                if token_permission == required_permission:
                    return True
        return False

    @staticmethod
    def get_permissions() -> list:
        """Determines if the required scope is present in the access token
        Args:
            required_permission (str): The scope required to access the resource
        """
        token = FlaskAuthWrapper.get_token_auth_header()
        unverified_claims = jwt.get_unverified_claims(token)
        if unverified_claims.get("permissions"):
            return unverified_claims["permissions"]
        return []

    @staticmethod
    def requires_auth(func):
        """Determines if the access token is valid
        """

        @wraps(func)
        def decorated(*args, **kwargs):
            token = FlaskAuthWrapper.get_token_auth_header()
            jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
            jwks = json.loads(jsonurl.read())
            try:
                unverified_header = jwt.get_unverified_header(token)
            except jwt.JWTError as jwt_error:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                     "Invalid header. "
                                     "Use an RS256 signed JWT Access Token"}, 401) from jwt_error
            if unverified_header["alg"] == "HS256":
                raise AuthError({"code": "invalid_header",
                                 "description":
                                     "Invalid header. "
                                     "Use an RS256 signed JWT Access Token"}, 401)
            rsa_key = {}
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = {
                        "kty": key["kty"],
                        "kid": key["kid"],
                        "use": key["use"],
                        "n": key["n"],
                        "e": key["e"]
                    }
            if rsa_key:
                try:
                    payload = jwt.decode(
                        token,
                        rsa_key,
                        algorithms=ALGORITHMS,
                        audience=AUTH0_AUDIENCE,
                        issuer="https://" + AUTH0_DOMAIN + "/"
                    )
                except jwt.ExpiredSignatureError as expired_sign_error:
                    raise AuthError({"code": "token_expired",
                                     "description": "token is expired"}, 401) from expired_sign_error
                except jwt.JWTClaimsError as jwt_claims_error:
                    raise AuthError({"code": "invalid_claims",
                                     "description":
                                         "incorrect claims,"
                                         " please check the audience and issuer"}, 401) from jwt_claims_error
                except Exception as exc:
                    raise AuthError({"code": "invalid_header",
                                     "description":
                                         "Unable to parse authentication"
                                         " token."}, 401) from exc

                _request_ctx_stack.top.current_user = payload
                return func(*args, **kwargs)
            raise AuthError({"code": "invalid_header",
                             "description": "Unable to find appropriate key"}, 401)

        return decorated


