#! /usr/bin/env python3

"""

    # application manager

    where the application is run and maintained and environments are prepared

"""

# internal package imports
import multiprocessing
import optparse
import signal
import json
import os

# internal module imports
from functools import partial
from itertools import chain
from logging import Formatter, StreamHandler, getLogger
from pathlib import Path
from hashlib import md5
from gzip import compress
from uuid import uuid4
from copy import copy

# internal sub-module imports
from logging.handlers import RotatingFileHandler

# external package imports
import jinja2

# external module imports
from flask import Flask, Response, request, g, session, abort

# external sub-module imports
from werkzeug.contrib.cache import FileSystemCache
from werkzeug.serving import make_ssl_devcert



def run_application(application: Flask, **kwargs) -> None:
    """
    Run the application but exit if interrupted (so that it can actually be 
    closed on-demand).
    """
    application.run(**kwargs)



def create_application(run_mode: str) -> Flask:
    """
    The goal here is to consolidate all the setup processes into their own
    functions and not muddy the waters with one giant setup function.
    """
    application = Flask(__name__)

    _initialise_settings(application, run_mode)
    _setup_logging(application)
    _setup_ssl(application)
    _setup_globals(application)
    _setup_templating(application)
    _setup_csrf(application)
    _setup_cors(application)
    _setup_compression(application)
    _setup_caching(application)

    return application



def _kill_application(application: Flask, signal, frame) -> None:
    application.logger.info('Interrupted with keyboard.')
    _halt_application(application)



def _halt_application(application: Flask) -> None:
    application.logger.info('Stopping...')
    quit()



def _initialise_settings(application: Flask, run_mode: str) -> None:
    """
    Use an instance folder and set up the application config. Prepare three
    environments: production, development, testing. Use development by default.
    Create the config file if it does not already exist.
    Add the config file data into the application config.
    """
    instance = Path(application.instance_path)
    if not instance.exists():
        instance.mkdir()

    cache_dir = instance / 'cache'
    if not cache_dir.exists():
        cache_dir.mkdir()

    configuration_file = instance / 'configuration.json'

    if not configuration_file.exists():
        host = os.getenv('hostname') or 'localhost'
        configuration = {
            'DEFAULT': {
                'PASSWORD_ROUNDS': 1,
                'CACHE_PERIOD': 6000,
                'CORS_ORIGIN': host,
                'SECRET_KEY': str(uuid4()),
                'CACHE_DIR': cache_dir.as_posix(),
                'PROCESSES': multiprocessing.cpu_count(),
                'LOG_LEVEL': 'DEBUG',
                'HOST_NAME': host,
                'CSRF_KEY': str(uuid4()),
                'PORT': 8080
            }
        }

        for mode in ['TESTING', 'PRODUCTION', 'DEVELOPMENT']:
            configuration[mode] = {
                'LOG_PATH': (instance / '{mode}.log'.format(mode=mode)).as_posix(),
                'RUN_MODE': mode,
                'DB_PATH': (instance / '{mode}.db'.format(mode=mode)).as_posix()
            }

        configuration['PRODUCTION'].update({
            'PASSWORD_ROUNDS': 5000000,
            'LOG_LEVEL': 'WARNING',
            'PORT': 80
        })

        with configuration_file.open('w') as output_file:
            json.dump(configuration, output_file, indent=4, sort_keys=True)

    with configuration_file.open('r') as input_file:
        configuration = json.load(input_file)
        application.config.update({**configuration['DEFAULT'], **configuration[run_mode]})



def _setup_globals(application: Flask) -> None:
    @application.before_request
    def set_globals():
        g.request_hash = md5(request.path.encode()).hexdigest()
        g.accept_encoding = request.headers.get('Accept-Encoding', '')



def _setup_logging(application: Flask) -> None:
    """
    Create a file logger and a console logger.
    """
    reset, bold, gray = '\033[0m', '\033[1m', '\033[30m'

    levels = {
        'debug': '\033[34m',
        'info': '\033[32m',
        'error': '\033[31m',
        'warning': '\033[33m'
    }

    class ColorLogFormatter(Formatter):
        def __init__(self, message):
            Formatter.__init__(self, message)

        def format(self, record):
            log = copy(record)
            level = log.levelname.lower()
            color, path, num, msg = levels[level], log.pathname, log.lineno, log.msg
            log.levelname = '{bold}{color}{level} {gray}{path}:{num} {reset}{bold}{msg}{reset}'.format(
                bold=bold,
                color=color,
                level=level,
                gray=gray,
                path=path,
                num=num,
                reset=reset,
                msg=msg
            )
            return Formatter.format(self, log)

    log_level = application.config['LOG_LEVEL']
    log_formatter = Formatter(
        '%(asctime)s - %(levelname)8s %(pathname)8s:%(lineno)4d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    color_log_formatter = ColorLogFormatter('%(levelname)s')

    application.logger.handlers = []
    application.logger.setLevel(log_level)

    console_handler = StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(color_log_formatter)

    file_handler = RotatingFileHandler(application.config['LOG_PATH'], maxBytes=100000, backupCount=1)
    file_handler.setLevel(log_level)
    file_handler.setFormatter(log_formatter)

    werkzeug_handler = getLogger('werkzeug')
    werkzeug_handler.setLevel(log_level)

    application.logger.addHandler(console_handler)
    application.logger.addHandler(file_handler)

    @application.after_request
    def log_request(response: Response) -> Response:
        """
        After each request log it to the application logger with the address,
        path, and status code.
        """
        path, address, code = request.path, request.remote_addr, response.status_code
        application.logger.info('Served {path} to {address} with status {code}'.format(
            path=path, address=address, code=code))
        return response



def _setup_ssl(application: Flask) -> None:
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



def _setup_caching(application: Flask) -> None:
    try:
        application.cache = FileSystemCache(application.config['CACHE_DIR'],
            default_timeout=application.config['CACHE_PERIOD'])
    except KeyError as error:
        application.logger.error('Error creating cache. Check CACHE_DIR & CACHE_PERIOD in config.')
        _halt_application(application)


    @application.before_request
    def return_cached() -> Response:
        if not request.values:
            response_data = application.cache.get(g.request_hash)
            if response_data:
                path, hash = request.path, g.request_hash[-7:]
                application.logger.debug('Retrieving \'{path}\' ({hash}) from cache'.format(
                    path=path, hash=hash))
                response = Response()
                response.set_data(response_data)
                return response


    @application.after_request
    def cache_request(response: Response) -> Response:
        if not request.values:
            application.cache.set(g.request_hash, response.get_data(), application.config['CACHE_PERIOD'])
        return response



def _setup_templating(application: Flask) -> None:
    """
    Automatically inject a csrf token into any form generated by jinja2.
    Use the randomly generated csrf key set in config for attribute lookup.
    """

    # application_path = Path(application.instance_path).parent / 'application'
    csrf_key = application.config['CSRF_KEY']

    def generate_csrf_token() -> str:
        if csrf_key not in session:
            session[csrf_key] = str(uuid4())
        return session[csrf_key]

    application.jinja_env.globals[csrf_key] = generate_csrf_token



def _setup_csrf(application: Flask) -> None:
    """
    Csrf protect ensures that forms can't be messed with.
    """
    @application.before_request
    def csrf_protect():
        g.accept_encoding = request.headers.get('Accept-Encoding', '')
        csrf_key = application.config['CSRF_KEY']
        if request.method == 'POST':
            token = session[csrf_key]
            if application.config['RUN_MODE'] == 'PRODUCTION':
                token = session.pop(csrf_key, None)
            if not token or token != request.form.get(csrf_key):
                application.logger.warning('Client tried to POST without csrf token.')
                abort(400)



def _setup_cors(application: Flask) -> None:
    @application.after_request
    def allow_origin(response: Response) -> Response:
        if request.method != 'OPTIONS' and 'Origin' in request.headers:
            response.headers.set(
                'Access-Control-Allow-Origin', application.config['CORS_ORIGIN']
            )
        return response



def _setup_compression(application: Flask) -> None:
    @application.after_request
    def compress_response(response: Response) -> Response:
        if 'gzip' not in g.accept_encoding.lower():
            return response

        response.direct_passthrough = False
        code_range = chain(range(400, 599), range(200, 299))

        if response.status_code not in code_range or 'Content-Encoding' in response.headers:
            return response

        data_length = len(response.data)
        response.data = compress(response.data)
        response.headers.set('Content-Encoding', 'gzip')
        response.headers.set('Vary', 'Accept-Encoding')
        response.headers.set('Content-Length', len(response.data))

        if application.config['LOG_LEVEL'] == 'DEBUG':
            delta = data_length - len(response.data)
            application.logger.debug('Saved {delta} bytes with gzip.'.format(delta=delta))

        return response



def main():
    """
    Interpret some command line arguments to run the application.
    """
    parser = optparse.OptionParser()
    parser.add_option('-M', '--mode', help="Mode in which to run the application")
    parser.add_option('-P', '--port', help="Override the port on which to run.")
    parser.add_option('-H', '--host', help="Override the host name.")
    parser.add_option('-C', '--cores', help="Run on x processes. Defaults to CPU count.")
    parser.add_option('-p', '--profile', action='store_true', help=optparse.SUPPRESS_HELP)
    options, _ = parser.parse_args()

    run_mode = (options.mode or 'development').upper()

    application = create_application(run_mode=run_mode)

    host = options.host or application.config['HOST_NAME']
    port = options.port or application.config['PORT']
    processes = options.cores or application.config['PROCESSES']
    ssl_context = (application.config['SSL_CERT'], application.config['SSL_KEY'])

    if options.profile:
        from werkzeug.contrib.profiler import ProfilerMiddleware
        application.config['PROFILE'] = True
        application.wsgi_app = ProfilerMiddleware(application.wsgi_app, restrictions=[30])
        application.logger.debug('Running profiler.')

    application.logger.info('Running application in {run_mode} mode.'.format(run_mode=run_mode))
    application.logger.info('Serving at {host}:{port}'.format(host=host, port=port))

    signal.signal(signal.SIGINT, partial(_kill_application, application))
    run_application(application, host=host, port=port, processes=processes, ssl_context=ssl_context)



if __name__ == '__main__':
    main()
