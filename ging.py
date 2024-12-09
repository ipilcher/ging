import os
import json
import datetime
import logging.config
import flask
import google_auth_oauthlib.flow
import googleapiclient.discovery
import google.oauth2.credentials


logging.config.dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'DEBUG',
        'handlers': ['wsgi']
    }
})


app = flask.Flask(__name__)
# This file should be created by the httpd startup script/service
with open('/tmp/ging-session-key', 'rb') as gsk:
    app.secret_key = gsk.read()

def get_oauth_flow():
    if not (flow := getattr(get_oauth_flow, '_flow', None)):
        url = flask.url_for('oauth2callback', _external=True)
        app.logger.info(f'OAUTH callback URL set to {url}')
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
                '/opt/ging/client-id.json', redirect_uri=url,
                scopes=[
                        'https://www.googleapis.com/auth/userinfo.profile',
                        'https://www.googleapis.com/auth/userinfo.email',
                        'openid'
                    ]
            )
        setattr(get_oauth_flow, '_flow', flow)
    return flow


@app.route('/')
def hello_world():
    response = flask.make_response('Hello world!', 200)
    response.mimetype = 'text/plain'
    return response

@app.route('/login')
def login():
    if 'oauth_creds' not in flask.session:
        return flask.redirect('auth')
    else:
        return flask.redirect('success')

@app.route('/auth')
def auth():
    #app.logger.debug(f'/auth: Secret key is {app.secret_key}')
    auth_url, state = get_oauth_flow().authorization_url()
    response = flask.make_response(flask.redirect(auth_url))
    #app.logger.debug(f'Setting session state: {state}')
    flask.session['state'] = state
    # This doesn't show the session cookie
    # app.logger.debug(f'Response headers: {response.headers}')
    return response

@app.route('/oauth2callback')
def oauth2callback():
    #app.logger.debug(f'/oauth2callback: Secret key is {app.secret_key}')
    #app.logger.debug(f'Cookie headers: {flask.request.headers.get("Cookie")}')
    session_state = flask.session.get('state')
    #app.logger.debug(f'Got session state: {session_state}')
    request_state = flask.request.args.get('state')
    #app.logger.debug(f'Got request state: {request_state}')
    # Disabling this check, because it doesn't work
    if session_state is None or session_state != request_state:
        return 'Danger, Will Robinson!', 400
    response = flask.make_response(flask.redirect('success'))
    del flask.session['state']
    flow = get_oauth_flow()
    flow.fetch_token(authorization_response=flask.request.url)
    flask.session['oauth_creds'] = flow.credentials.to_json()
    return response

@app.route('/success')
def success():
    #app.logger.debug(f'/success: Secret key is {app.secret_key}')
    if not (creds_json := flask.session.get('oauth_creds')):
        return "You don't have credentials!", 400
    #app.logger.debug(f'Got credentials: {creds_json}')
    creds_dict = json.loads(creds_json)
    app.logger.debug(f'expiry: {creds_dict['expiry']}')
    expiry = datetime.datetime.fromisoformat(creds_dict['expiry'])
    creds_dict['expiry'] = expiry.replace(tzinfo=None)
    creds = google.oauth2.credentials.Credentials(**creds_dict)
    service = googleapiclient.discovery.build('people', 'v1', credentials=creds)
    request = service.people().get(
            resourceName='people/me', personFields='names,emailAddresses'
        )
    profile = request.execute()
    response = flask.make_response(profile)
    response.mimetype = 'application/json'
    return response
    #response = flask.make_response('Great success!')
    #response.mimetype = 'text/plain'
    #return response

if __name__ == '__main__':
        app.run()
