"""helpers for user-authentication apps (i.e., apps that use
OAuth 2.0 Authorization Code Grant workflow)"""
import json
import uuid

def contacts(msgraph):
    """Generator to return contacts for current authenticated user.
    msgraph = user-authenticated GraphConnect instance"""
    next_page = 'me/contacts'
    while next_page:
        response = msgraph.get(next_page)
        for contact in response.json().get('value', None):
            yield contact
        next_page = response.json().get('@odata.nextLink', None)

def messages(msgraph, mailfolder='inbox'):
    """Generator to return messages from a specified folder.
    msgraph = user-authenticated GraphConnect instance
    mailfolder = name or id of mail folder; for example, 'Inbox' or a
                 120-character ID value"""
    next_page = 'me/mailFolders/' + mailfolder + '/messages'
    while next_page:
        response = msgraph.get(next_page)
        for msg in response.json().get('value', None):
            yield msg
        next_page = response.json().get('@odata.nextLink', None)

def openext(msgraph=None, entity='me', action=None, extension=None, values=None):
    """helper for openExtension key/value pairs.

    Arguments:
    msgraph = user-authenticated GraphConnect instance
    entity = Graph entity type (currently only supports 'me')
    action = type of action to take ('create', 'get', 'update', or 'delete')
    extension = extension name; reverse DNS approach is common, for example
                'com.Contoso.infotype'
    values = dictionary of key/value pairs (required for create/update)

    Return values:
    'get' actions returns a dict() of the key/value pairs for the extension
    create/update/delete actions return a Requests response object

    Note that this function requires the "Directory.AccessAsUser.All" scope.
    """

    # validate arguments ...
    if action not in ['create', 'get', 'update', 'delete']:
        raise ValueError('openext(): invalid action ({0})'.format(action))
    if not all([msgraph, entity, action, extension]):
        raise ValueError('openext(): required arguments missing')
    if action in ['create', 'update'] and not values:
        raise ValueError('openext(): {0} requires values'.format(action))

    # handle each action ...
    if action == 'create':
        request_body = \
            '{"@odata.type": "Microsoft.Graph.OpenTypeExtension", ' + \
            '"extensionName": "' + extension + '", ' + \
            ', '.join(['"' + key + '": "' + value + '"'
                       for key, value in values.items()]) + '}'
        return msgraph.post('me/extensions', data=request_body)
        # if the extension alreadt exists, POST returns a 409
    elif action == 'get':
        response = msgraph.get('me?$select=id&$expand=extensions')
        for extdata in response.json().get('extensions'):
            if extdata['id'] == extension:
                extdata.pop('@odata.type', None)
                extdata.pop('id', None)
                return extdata
        return dict() # requested extension not found in response
    elif action == 'update':
        return msgraph.patch('me/extensions/' + extension,
                             data=json.dumps(values))
    elif action == 'delete':
        return msgraph.delete('me/extensions/' + extension)

def sendmail(msgraph, subject=None, recipients=None, html=None):
    """Helper to send email from current user.
    msgraph = user-authenticated GraphConnect instance
    subject = email subject (required)
    recipients = list of recipient email addresses (required)
    html = html body of the message (required)

    Returns the response from the POST to the sendmail API.
    """

    # validate arguments
    if not all([msgraph, subject, recipients, html]):
        raise ValueError('sendmail(): required arguments missing')

    # convert recipients to the list of dicts required by sendmail API
    recipient_list = [dict(EmailAddress=dict(Address=address))
                      for address in recipients]

    # create HTTP request headers, including client request ID for
    # telemtry/instrumentation/debugging
    headers = msgraph.http_request_headers()
    headers.update({'client-request-id' : str(uuid.uuid4()),
                    'return-client-request-id' : 'true'})

	# Create the email message in the required format
    email_msg = {'Message': {'Subject': subject,
                             'Body': {'ContentType': 'HTML', 'Content': html},
                             'ToRecipients': recipient_list},
                 'SaveToSentItems': 'true',
                 'Attachments': []}

    return msgraph.post(url='me/microsoft.graph.sendMail',
                        headers=headers,
                        data=json.dumps(email_msg),
                        verify=False,
                        params=None)
