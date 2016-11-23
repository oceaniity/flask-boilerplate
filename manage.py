#! /usr/bin/env python3
"""

    # application manager

    where the application is run and maintained and environments are prepared

"""

# internal package imports
import optparse
import signal
import os
#internal module imports
from pathlib import Path
from uuid import uuid4
from functools import partial
# external module imports

def run_application(application, **kwargs):
    """
    Run the application but exit if interrupted (so that it can actually be 
    closed on-demand).
    """
    application.run(**kwargs)

def create_application(run_mode):
    """
    The goal here is to consolidate all the setup processes into their own
    functions and not muddy the waters with one giant setup function.
    """
    from flask import Flask

    application = Flask(__name__)

    _initialise_settings(application, run_mode)
    _setup_logging(application)
    _setup_ssl(application)
    _setup_templating(application)
    _setup_interceptors(application)

    return application

def _kill_application(application, signal, frame):
    application.logger.info('Interrupted with keyboard. Shutting down...')
    quit()

def _halt_application(application):
    application.logger.info('Stopping...')
    quit()

def _initialise_settings(application, run_mode):
    """
    Use an instance folder and set up the application config. Prepare three
    environments: production, development, testing. Use development by default.
    Create the config file if it does not already exist.
    Add the config file data into the application config.
    """
    import json
    import multiprocessing
    
    instance = Path(application.instance_path)
    if not instance.exists():
        instance.mkdir()

    configuration_file = instance / 'configuration.json'

    if not configuration_file.exists():
        with configuration_file.open('w') as output_configuration:

            configuration = {
                'DEFAULT': {
                    'LOG_LEVEL': 'DEBUG',
                    'LOG_PATH': (instance / '{}.log'.format(run_mode.lower())).as_posix(),
                    'SECRET_KEY': str(uuid4()),
                    'CSRF_KEY': str(uuid4()),
                    'RUN_MODE': 'DEVELOPMENT',
                    'CORS_ORIGIN': 'localhost',
                    'HOST_NAME': 'localhost',
                    'PORT': 8080,
                    'PASSWORD_ROUNDS': 1,
                    'CPU_CORES': multiprocessing.cpu_count()
                },
                'TESTING': {
                    'RUN_MODE': 'TESTING'
                },
                'PRODUCTION': {
                    'LOG_LEVEL': 'WARNING',
                    'RUN_MODE': 'PRODUCTION',
                    'PORT': 80,
                    'CORS_ORIGIN': os.environ.get('hostname') or 'localhost',
                    'HOST_NAME': os.environ.get('hostname') or 'localhost',
                    'PASSWORD_ROUNDS': 3000000  
                }
            }
            
            json.dump(configuration, output_configuration, indent=4, sort_keys=True)

    with configuration_file.open('r') as input_configuration:
        configuration = json.load(input_configuration)
        application.config.update({
            key.upper(): value for key, value in {
                **configuration.get('DEFAULT'),
                **configuration.get(run_mode, {})
            }.items()
        })

def _setup_logging(application):
    """
    Create a file logger and a console logger.
    """
    from logging import Formatter, StreamHandler, getLogger
    from logging.handlers import RotatingFileHandler

    
    log_level = application.config['LOG_LEVEL']
    log_formatter = Formatter(
        '%(asctime)s - %(levelname)8s {%(pathname)8s:%(lineno)4d} - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    application.logger.handlers = []
    application.logger.setLevel(log_level)

    console_handler = StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(log_formatter)

    file_handler = RotatingFileHandler(application.config['LOG_PATH'], maxBytes=100000, backupCount=1)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(log_formatter)

    werkzeug_handler = getLogger('werkzeug')
    werkzeug_handler.setLevel(log_level)

    application.logger.addHandler(console_handler)
    application.logger.addHandler(file_handler)

def _setup_ssl(application):
    from werkzeug.serving import make_ssl_devcert
    instance = Path(application.instance_path)
    if not (instance/'ssl.crt').exists():
        application.logger.info('No SSL certificate detected. Generating one...')
        try:
            cert, key = make_ssl_devcert((instance/'ssl').as_posix(), host=application.config['HOST_NAME'])
        except ImportError as error:
            application.logger.error(str(error))
            _halt_application(application)
    application.config.update({
        'SSL_CERT': (instance/'ssl.crt').as_posix(),
        'SSL_KEY': (instance/'ssl.key').as_posix()
    })

def _setup_templating(application):
    """
    Automatically inject a csrf token into any form generated by jinja2.
    Use the randomly generated csrf key set in config for attribute lookup.
    """
    import jinja2
    from flask import session

    # application_path = Path(application.instance_path).parent / 'application'
    csrf_key = application.config['CSRF_KEY']

    def generate_csrf_token():
        if csrf_key not in session:
            session[csrf_key] = str(uuid4())
        return session[csrf_key]

    application.jinja_env.globals[csrf_key] = generate_csrf_token

def _setup_interceptors(application):
    """
    Set up a few interceptors that act on requests.
    Csrf protect ensures that forms can't be messed with.
    Allow origin prevents unsightly CORS preflight requests.
    Compress response saves some data by compressing responses where compatible.
    """
    from itertools import chain
    from flask import request, redirect, g, abort
    from gzip import compress

    @application.before_request
    def csrf_protect():
        g.ACCEPT_ENCODING = request.headers.get('Accept-Encoding', '')
        csrf_key = application.config['CSRF_KEY']
        if request.method == 'POST':
            token = session[csrf_key]
            if application.config['RUN_MODE'] == 'PRODUCTION':
                token = session.pop(csrf_key, None)
            if not token or token != request.form.get('_csrf_token'):
                application.logger.warning('Client tried to POST without csrf token.')
                abort(404)

    @application.after_request
    def log_request(response):
        """
        After each request log it to the application logger with the address,
        path, and status code.
        """
        application.logger.info('Served {} to {} with status {}'.format(
            request.path, request.remote_addr, response.status_code))
        return response

    @application.after_request
    def allow_origin(response):
        if request.method != 'OPTIONS' and 'Origin' in request.headers:
            response.headers.set(
                'Access-Control-Allow-Origin', application.config['CORS_ORIGIN']
            )
        return response

    @application.after_request
    def compress_response(response):
        accept_encoding = g.ACCEPT_ENCODING
        if 'gzip' not in accept_encoding.lower():
            return response

        response.direct_passthrough = False
        if response.status_code not in chain(range(400, 599), range(200, 299)) or 'Content-Encoding' in response.headers:
            return response

        original_length = len(response.data)
        response.data = compress(response.data)
        response.headers.set('Content-Encoding', 'gzip')
        response.headers.set('Vary', 'Accept-Encoding')
        response.headers.set('Content-Length', len(response.data))

        if application.config['LOG_LEVEL'] == 'DEBUG':
            saved_bytes = original_length - len(response.data)
            application.logger.debug('Saved {} bytes with gzip.'.format(saved_bytes))

        return response


def main():
    """
    Interpret some command line arguments to run the application.
    """
    option_parser = optparse.OptionParser()
    option_parser.add_option('-M', '--mode',
        help="Mode in which to run the application")
    option_parser.add_option('-P', '--port',
        help="Override the port on which to run.")
    option_parser.add_option('-H', '--host',
        help="Override the host name.")
    option_parser.add_option('-T', '--test',
        help="Run tests.")
    option_parser.add_option('-C', '--cores',
        help="Number of cores to run on. Defaults to available core count.")
    option_parser.add_option('-p', '--profile', action='store_true', dest='profile',
        help=optparse.SUPPRESS_HELP)
    options, _ = option_parser.parse_args()

    run_mode = (options.mode or 'development').upper()

    application = create_application(run_mode=run_mode)

    host = options.host or application.config['HOST_NAME']
    port = options.port or application.config['PORT']
    cores = options.cores or application.config['CPU_CORES']
    ssl = (application.config['SSL_CERT'], application.config['SSL_KEY'])

    if options.profile:
        from werkzeug.contrib.profiler import ProfilerMiddleware
        application.config['PROFILE'] = True
        application.wsgi_app = ProfilerMiddleware(application.wsgi_app, restrictions=[30])
        application.logger.debug('Running profiler.')

    application.logger.info('Running application in {} mode.'.format(run_mode))
    application.logger.info('Serving at {}:{}'.format(host, port))

    signal.signal(signal.SIGINT, partial(_kill_application, application))
    run_application(application, host=host, port=port, processes=cores, ssl_context=ssl)

if __name__ == '__main__':
    main()
