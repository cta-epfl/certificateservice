from datetime import date, datetime, timedelta
from certificateservice.certificate import (
    CertificateError,
    certificate_validity,
    verify_certificate,
)
from functools import wraps
import os
import stat
import re
import secrets
import importlib.metadata
from flask import (
    Blueprint,
    Flask,
    make_response,
    redirect,
    request,
    session,
    render_template,
)
from flask_cors import CORS

import logging

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn='https://452458c2a6630292629364221bff0dee@o4505709665976320'
    + '.ingest.sentry.io/4505709666762752',
    integrations=[
        FlaskIntegration(),
    ],
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0,
    release='certificateservice:'
    + importlib.metadata.version("certificateservice"),
    environment=os.environ.get('SENTRY_ENVIRONMENT', 'dev'),
)

# from flask_oidc import OpenIDConnect
logger = logging.getLogger(__name__)


def urljoin_multipart(*args):
    """Join multiple parts of a URL together, ignoring empty parts."""
    logger.info('urljoin_multipart: %s', args)
    return '/'.join(
        [
            arg.strip('/')
            for arg in args
            if arg is not None and arg.strip('/') != ''
        ]
    )


try:
    from jupyterhub.services.auth import HubOAuth

    auth = HubOAuth(
        api_token=os.environ['JUPYTERHUB_API_TOKEN'], cache_max_age=60
    )
except Exception:
    logger.warning('Auth system not configured')
    auth = None

bp = Blueprint('certificateservice', __name__, template_folder='templates')

url_prefix = os.getenv('JUPYTERHUB_SERVICE_PREFIX', '').rstrip('/')

default_chunk_size = 10 * 1024 * 1024


def create_app():
    app = Flask(__name__)
    CORS(app)

    app.config['SECRET_KEY'] = os.environ.get(
        'FLASK_SECRET', secrets.token_bytes(32)
    )
    app.secret_key = app.config['SECRET_KEY']

    app.config['CTACS_CERTIFICATE_DIR'] = os.environ.get(
        'CTACS_CERTIFICATE_DIR', './certificate/'
    )
    app.config['CTACS_CABUNDLE'] = os.environ.get(
        'CTACS_CABUNDLE', '/etc/cabundle.pem'
    )
    app.config['CTACS_CLIENTCERT'] = os.environ.get(
        'CTACS_CLIENTCERT', '/tmp/x509up_u1000'
    )
    app.config['CTACS_DISABLE_ALL_AUTH'] = (
        os.getenv('CTACS_DISABLE_ALL_AUTH', 'False') == 'True'
    )

    # Check certificate folder
    os.makedirs(app.config['CTACS_CERTIFICATE_DIR'], exist_ok=True)

    # Check certificates and their validity on startup
    cabundle_file = app.config['CTACS_CABUNDLE']
    cert_file = app.config['CTACS_CLIENTCERT']
    try:
        cabundle = open(cabundle_file, 'r').read()
        with open(cert_file, 'r') as f:
            certificate = f.read()
            verify_certificate(cabundle, certificate)
            if certificate_validity(certificate) <= datetime.now():
                logger.warning('Configured certificate expired')
    except FileNotFoundError:
        logger.warning('No configured certificate')
    except CertificateError:
        logger.warning('Invalid configured certificate')

    return app


app = create_app()


@app.errorhandler(CertificateError)
def handle_bad_request(e):
    sentry_sdk.capture_exception(e)
    return e.message, 400


def download_authenticated(f):
    """Decorator for authenticating with the Hub via OAuth"""

    @wraps(f)
    def decorated(*args, **kwargs):
        if app.config['CTACS_DISABLE_ALL_AUTH']:
            return f({'name': 'anonymous', 'admin': True}, *args, **kwargs)
        else:
            if auth is None:
                return (
                    'Unable to use jupyterhub to verify access to this\
                    service. At this time, the certificateservice uses jupyterhub\
                    to control access to protected resources',
                    500,
                )

            header = request.headers.get('Authorization')
            if header and header.startswith('Bearer '):
                header_token = header.removeprefix('Bearer ')
            else:
                header_token = None

            service_token = (
                session.get('service-token')
                or request.args.get('service-token')
                or header_token
            )

            if service_token:
                service = auth.user_for_token(service_token)
                if service is not None and not auth.check_scopes(
                    'custom:certificateservice:download', service
                ):
                    return (
                        'Access denied, token scopes are insufficient. '
                        + 'If you need access to this service, please '
                        + 'contact CTA-CH DC team at EPFL.',
                        403,
                    )
            else:
                user = None

            # Get user token
            user_token = request.args.get('user-token')

            if user_token:
                user = auth.user_for_token(user_token)
                if user is not None and not auth.check_scopes(
                    'access:services!service=certificateservice', user
                ):
                    return (
                        'Access denied, token scopes are insufficient. '
                        + 'If you need access to this service, please '
                        + 'contact CTA-CH DC team at EPFL.',
                        403,
                    )
            else:
                user = None

            if user:
                return f(user, *args, **kwargs)
            else:
                return "invalid user permissions for certificate service", 500

    return decorated


def upload_authenticated(f):
    # TODO: here do a permission check;
    # in the future, the check will be done with rucio maybe
    """Decorator for authenticating with the Hub via OAuth"""

    @wraps(f)
    def decorated(*args, **kwargs):
        if app.config['CTACS_DISABLE_ALL_AUTH']:
            return f({'name': 'anonymous', 'admin': True}, *args, **kwargs)
        else:
            if auth is None:
                return (
                    'Unable to use jupyterhub to verify access to this\
                    service. At this time, the certificateservice uses jupyterhub\
                    to control access to protected resources',
                    500,
                )

            header = request.headers.get('Authorization')
            if header and header.startswith('Bearer '):
                header_token = header.removeprefix('Bearer ')
            else:
                header_token = None

            token = (
                session.get('token')
                or request.args.get('token')
                or header_token
            )

            if token:
                user = auth.user_for_token(token)
                if user is not None and not auth.check_scopes(
                    'access:services!service=certificateservice', user
                ):
                    return (
                        'Access denied, token scopes are insufficient. '
                        + 'If you need access to this service, please '
                        + 'contact CTA-CH DC team at EPFL.',
                        403,
                    )
            else:
                user = None

            if user:
                return f(user, *args, **kwargs)
            else:
                # redirect to login url on failed auth
                state = auth.generate_state(next_url=request.path)
                response = make_response(
                    redirect(auth.login_url + '&state=%s' % state)
                )
                response.set_cookie(auth.state_cookie_name, state)
                return response

    return decorated


@app.route(url_prefix + '/')
@upload_authenticated
def login(user):
    token = session.get('token') or request.args.get('token')
    return render_template('index.html', user=user, token=token)


def user_to_path_fragment(user):
    if isinstance(user, dict):
        user = user['name']

    return re.sub('[^0-1a-z]', '_', user.lower())


@app.route(url_prefix + '/certificate', methods=['GET'])
@download_authenticated
def get_certificate(user=None):
    cert = app.config['CTACS_CLIENTCERT']
    own_certificate = False

    if user is not None:
        filename = user_to_path_fragment(user) + ".crt"
        own_certificate_file = os.path.join(
            app.config['CTACS_CERTIFICATE_DIR'], filename
        )

        if os.path.isfile(own_certificate_file):
            own_certificate = True
            cert = own_certificate_file

    allowed_users = app.config['CTACS_MAIN_CERT_ALLOWED_USER'].split(',')
    if not user_to_path_fragment(user) in allowed_users:
        raise "You do not have any certificate configured"

    try:
        with open(cert, 'r') as f:
            certificate = f.read()
            if certificate_validity(certificate) <= datetime.now():
                if own_certificate:
                    raise 'Your configured certificate is invalid, ' +\
                        'please refresh it.'
                else:
                    logger.exception('outdated main certificate')
                    raise 'Service certificate invalid please contact us.'

            return {
                'certificate': certificate,
                'cabundle': open(app.config['CTACS_CABUNDLE'], 'r').read(),
            }, 200
    except FileNotFoundError:
        raise 'no valid certificate configured'


@app.route(url_prefix + '/certificate', methods=['POST'])
@upload_authenticated
def upload_certificate(user):
    filename = user_to_path_fragment(user) + ".crt"
    certificate_file = os.path.join(
        app.config['CTACS_CERTIFICATE_DIR'], filename
    )

    certificate = request.json.get('certificate')

    try:
        cabundle = open(app.config['CTACS_CABUNDLE'], 'r').read()
    except FileNotFoundError:
        return (
            'certificateservice cabundle not configured, '
            + 'please contact the administrator',
            500,
        )
    verify_certificate(cabundle, certificate)

    validity = certificate_validity(certificate)
    if validity.date() > date.today() + timedelta(days=7):
        return (
            'certificate validity too long, please generate a '
            + 'short-lived (max 7 day) proxy certificate for uploading. '
            + 'Please see https://ctaodc.ch/ for more details.',
            400,
        )
    if validity <= datetime.today():
        return 'certificate expired', 400

    with open(certificate_file, 'w') as f:
        f.write(certificate)
    os.chmod(certificate_file, stat.S_IWUSR | stat.S_IRUSR)

    return {'message': 'Certificate stored', 'validity': validity}, 200


@app.route(url_prefix + '/main-certificate', methods=['POST'])
@upload_authenticated
def upload_main_certificate(user):
    if not isinstance(user, dict) or user['admin'] is not True:
        return 'access denied', 401

    data = request.json
    certificate = data.get('certificate', None)
    cabundle = data.get('cabundle', None)

    if certificate is None and cabundle is None:
        return 'requests missing certificate or cabundle', 400

    if cabundle is None:
        cabundle = open(app.config['CTACS_CABUNDLE'], 'r').read()
    if certificate is None:
        certificate = open(app.config['CTACS_CLIENTCERT'], 'r').read()
    verify_certificate(cabundle, certificate)

    if certificate and certificate_validity(certificate).date() > (
        date.today() + timedelta(days=7)
    ):
        return (
            'certificate validity too long, please generate a '
            + 'short-lived (max 7 day) proxy certificate for uploading. '
            + 'Please see https://ctaodc.ch/ for more details.',
            400,
        )

    updated = set()
    if certificate is not None:
        with open(app.config['CTACS_CLIENTCERT'], 'w') as f:
            f.write(certificate)
            updated.add('Certificate')
        os.chmod(
            app.config['CTACS_CLIENTCERT'], stat.S_IWUSR | stat.S_IRUSR
        )  # Write by owner
    if cabundle is not None:
        with open(app.config['CTACS_CABUNDLE'], 'w') as f:
            f.write(cabundle)
            updated.add('CABundle')
        os.chmod(
            app.config['CTACS_CABUNDLE'],
            stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
        )

    return {
        'message': ' and '.join(updated) + ' stored',
        'cabundleUploaded': cabundle is not None,
        'certificateUploaded': certificate is not None,
    }, 200


@app.route(url_prefix + '/health')
def health():
    # TODO: health status check
    return 'OK', 200

    # if r.status_code in [200, 207]:
    #     return 'OK', 200
    # else:
    #     logger.error('service is unhealthy: %s', r.content.decode())
    #     return 'Unhealthy!', 500


@app.route(url_prefix + '/oauth_callback')
def oauth_callback():
    code = request.args.get('code', None)
    if code is None:
        return 'Error: oauth callback code', 403

    # validate state field
    arg_state = request.args.get('state', None)
    cookie_state = request.cookies.get(auth.state_cookie_name)
    if arg_state is None or arg_state != cookie_state:
        # state doesn't match
        return 'Error: oauth callback invalid state', 403

    token = auth.token_for_code(code)
    # store token in session cookie
    session['token'] = token
    next_url = auth.get_next_url(cookie_state) or url_prefix
    response = make_response(redirect(next_url))
    return response
