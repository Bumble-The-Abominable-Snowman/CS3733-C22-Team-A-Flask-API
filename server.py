
from FlaskAuthWrapper import *
from FlaskAppHandler import FlaskAppHandler
from FlaskApiHandler import FlaskApiHandler
import constants

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True


@app.errorhandler(AuthError)
def handle_auth_error(ex: AuthError) -> Response:
    """
    serializes the given AuthError as json and sets the response status code accordingly.
    :param ex: an auth error
    :return: json serialized ex response
    """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


auth = FlaskAuthWrapper(app)

FlaskAppHandler(app, auth)
FlaskApiHandler(app, auth)

if __name__ == "__main__":
    app.run()


