"""code samples for graphhelper"""
import json
import pprint

from graphhelper import UserConnect, messages, openext, sendmail, contacts

def sample_contacts(count):
    """Example of retrieving contacts from the Graph API.
    count = number of contacts to retrieve"""
    msgraph = UserConnect()
    for _, contact in zip(range(count), contacts(msgraph)):
        print(contact['displayName'], contact['companyName'], contact['jobTitle'])

def sample_inbox(count):
    """Example of reading messages from Inbox.
    count = number of emails to retrieve"""
    msgraph = UserConnect()
    for _, msg in zip(range(count), messages(msgraph, 'inbox')):
        pprint.pprint(msg['from']['emailAddress'])

def sample_mailfolder(count):
    """Example of reading messages from a mail folder.
    count = number of emails to retrieve"""
    msgraph = UserConnect()
    # test folder under dmahugh@microsoft.com
    devxfolder = 'AAMkAGM1M2U4NmRmLTNlM2EtNGI1OS05NjdiLTMzZTkwZjY4OTczYwAuA' + \
        'AAAAABDUFqEnZH9R7gLJNckH3iZAQASMWt54A4KQp9V1DmJDllnAAAwpG0IAAA='
    for _, msg in zip(range(count), messages(msgraph, devxfolder)):
        pprint.pprint(msg['from']['emailAddress'])

def sample_me():
    """Example of reading 'me' properties."""
    msgraph = UserConnect()
    print(msgraph.me['id'])
    print(msgraph.me['displayName'])
    print(msgraph.me['userPrincipalName'])

def sample_openext():
    """Example of openext() helper function."""

    # this example requires admin consent scopes ...
    settings = json.loads(open('config/openext.json').read())
    msgraph = UserConnect(config=settings)

    extname = 'com.graphhelper.test'
    print('testing openext(), extension name = {0}'.format(extname))

    response = openext(msgraph, entity='me', action='delete', extension=extname)
    print('DELETE response: {0}'.format(response))

    response = openext(msgraph, entity='me', action='create', extension=extname,
                       values=dict(color='blue', theme='dark'))
    print('CREATE response: {0}'.format(response))

    response = openext(msgraph, entity='me', action='get', extension=extname)
    print('GET response: {0}'.format(str(response)))

    response = openext(msgraph, entity='me', action='update', extension=extname,
                       values=dict(color='updated color',
                                   theme='updated theme'))
    print('UPDATE response: {0}'.format(response))

    response = openext(msgraph, entity='me', action='get', extension=extname)
    print('GET response: {0}'.format(str(response)))

def sample_sendmail():
    """Example of sendmail() helper function."""
    msgraph = UserConnect()
    response = sendmail(msgraph, 'graphhelper sendmail() sample',
                        [msgraph.me['userPrincipalName']], # send to current user
                        'body of test message')
    print(response)

if __name__ == '__main__':
    sample_inbox(5)
    #sample_mailfolder(5)
    #sample_contacts(5)
    #sample_sendmail()
    sample_openext()
    #sample_me()
