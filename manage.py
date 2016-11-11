#! /usr/bin/env python3
"""

    # application manager

    where the application is run and maintained and environments are prepared

"""

# internal package imports
import logging
import argparse
import configparser
import gzip
#internal module imports
from pathlib import Path
from uuid import uuid4

def run_application(application, **kwargs):
    try:
        application.run(**kwargs)
    except (KeyboardInterrupt, SystemExit):
        raise

def create_application(run_mode):
    from flask import Flask

    application = Flask(__name__)

    _initialise_settings(application, run_mode)
    _setup_logging(application)
    _setup_templating(application)
    # _setup_bundling(application)
    _setup_interceptors(application)

    return application

def _initialise_settings(application, run_mode):
    instance = Path(application.instance_path)
    
    if not instance.exists():
        instance.mkdir()

    configuration_file = instance / 'configuration.ini'
    configuration = configparser.ConfigParser()

    if not configuration_file.exists():
        with configuration_file.open('w') as output_file:
            configuration['DEFAULT'] = {
                'LOG_LEVEL': 'DEBUG',
                'LOG_PATH': (instance / '{}.log'.format(run_mode)).as_posix(),
                'SECRET_KEY': '{}'.format(uuid4().hex),
                'CSRF_KEY': '{}'.format(uuid4().hex),
                'RUN_MODE': 'DEVELOPMENT',
                'CORS_ORIGIN': 'localhost',
                'PORT': 5000,
                'PASSWORD_ROUNDS': 1,
                'FLASK_ASSETS_USE_S3': False
            }

            configuration['TESTING'] = {
                'RUN_MODE': 'TESTING'
            }

            configuration['PRODUCTION'] = {
                'LOG_LEVEL': 'WARNING',
                'RUN_MODE': 'PRODUCTION',
                'PORT': 443,
                'CORS_ORIGIN': 'client.bpanz.com'
                'PASSWORD_ROUNDS': 3000000,
                'FLASK_ASSETS_USE_S3': True
            }

            configuration.write(output_file)

    configuration.read(configuration_file.as_posix())

    application.config.update({
        key.upper(): value for key, value in configuration[run_mode].items()
    })

def _setup_logging(application):
    log_level = application.config.get('LOG_LEVEL')

    application.logger.handlers = []
    application.logger.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    application.logger.addHandler(console_handler)

def _setup_templating(application):
    import jinja2
    from flask import session

    application_path = Path(application.instance_path).parent / 'application'

    def generate_csrf_token():
        csrf_key = application.config['CSRF_KEY']
        
        if csrf_key not in session:
            session[csrf_key] = uuid4().hex

        return session[csrf_key]

    application.jinja_env.globals[csrf_key] = generate_csrf_token

# def _setup_bundling(application):
#     from flask_assets import Environments, Bundle
#     assets = Environment(application)

def _setup_interceptors(application):
    from flask import request, response, g, abort

    @application.before_request
    def csrf_protect():
        g.set('ACCEPT_ENCODING', request.headers.get('Accept-Encoding', ''))
        csrf_key = application.config['CSRF_KEY']
        if request.method == 'POST':
            token = session.get(csrf_key)
            if application.config['RUN_MODE'] == 'PRODUCTION':
                token = session.pop(csrf_key, None)
            if not token or token != request.form.get('_csrf_token'):
                abort(404)

    @application.after_request
    def allow_origin(response):
        if request.method != 'OPTIONS' and 'Origin' in request.headers:
            response.headers.set(
                'Access-Control-Allow-Origin', application.config.get('CORS_ORIGIN')
            )
        return response

    @application.after_request
    def compress_response(response):
        accept_encoding = g.get('ACCEPT_ENCODING')
        if 'gzip' not in accept_encoding.lower():
            return response

        response.direct_passthrough = False

        if response.status_code not in range(200, 299) or 'Content-Encoding' in response.headers:
            return response

        response.data = gzip.compress(response.data)
        response.headers.set('Content-Encoding', 'gzip')
        response.headers.set('Vary', 'Accept-Encoding')
        response.headers.set('Content-Length', len(response.data))

        return response


def main():
    argument_parser = argparse.ArgumentParser(description='dashboard application runner')
    argument_parser.add_argument('mode', type=str, help='just dev or testing for now')
    arguments = argument_parser.parse_args()

    run_mode = arguments.mode.upper()

    if run_mode in ['DEVELOPMENT', 'TESTING']:
        application = create_application(run_mode=run_mode)

        run_application(application, host='127.0.0.1', port=application.config.get('PORT'))

    else:
        raise Exception()

if __name__ == '__main__':
    main()
