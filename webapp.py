"""Sample implementation of a web app using the graphhelper module."""
import os

import bottle
from bottle import route, view

from graphhelper import UserConnect, messages

def render_table(dataset, columns):
    """Convert list of dictionaries to HTML string for display."""
    coltuples = [column.split(':') for column in columns.split(' ')]
    html_strings = ['<table class = "sample">']
    html_strings.append('<tr>')
    for fldname, _ in coltuples:
        html_strings.append('<th>' + fldname.capitalize() + '</th>')
    html_strings.append('</tr>')
    for entity in dataset:
        html_strings.append('<tr>')
        for fldname, nchars in coltuples:
            fldsize = int(nchars)
            if fldname in entity and entity[fldname]:
                html_strings.append( \
                    '<td>' + str(entity[fldname])[:fldsize].ljust(fldsize) + '</td>')
            else:
                html_strings.append('<td></td>') # missing value
        html_strings.append('</tr>')
    html_strings.append('</table>')
    return ''.join(html_strings)

msgraph = UserConnect()

@route('/')
@view('homepage')
def home():
    """Render the home page."""
    if msgraph.state['loggedin']:
        inbox = messages(msgraph, 'inbox')
        emails = []
        for _ in range(10):
            email = next(inbox)
            email_date = email['receivedDateTime'][:10]
            sender = '{0} ({1})'.format(email['from']['emailAddress'].get('name', ''),
                                        email['from']['emailAddress'].get('address', ''))
            subject = email['subject']
            emails.append(dict(date=email_date, sender=sender, subject=subject))
        return dict(sample='INBOX',
                    sampledata=render_table(emails, 'date:10 sender:35 subject:35'))
    else:
        return dict(sample=None, sampledata=None)

@route('/login')
def login():
    """Prompt user to authenticate."""
    msgraph.login()

@route('/login/authorized')
def authorized():
    """Fetch access token for authenticated user."""
    return msgraph.get_token()

@route('/logout')
def logout():
    """Log out from MS Graph connection."""
    msgraph.logout()

if __name__ == '__main__':
    @bottle.route('/static/<filepath:path>')
    def server_static(filepath):
        """Handler for static files, used with the development server."""
        PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
        STATIC_ROOT = os.path.join(PROJECT_ROOT, 'static').replace('\\', '/')
        return bottle.static_file(filepath, root=STATIC_ROOT)
    bottle.run(app=bottle.app(), server='wsgiref', host='localhost', port=5000)
