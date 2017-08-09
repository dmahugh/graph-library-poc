% from webapp import msgraph

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>graph-python-quickstart</title>
    <link rel="stylesheet" type="text/css" href="/static/css/bootstrap.min.css" />
    <link rel="stylesheet" type="text/css" href="/static/css/site.css?version=1.01" />
    <script src="/static/scripts/modernizr-2.6.2.js"></script>
</head>

<body>
    <div class="container homepage-container">

        % if msgraph.state['loggedin']:

            <h2>{{ sample.upper() }} sample</h2>
            {{! sampledata }}
            <table class="homepage">
                <tr>
                    <td><button type="button" class="btn btn-success btn-md" onclick="window.location.href='/logout'">Disconnect</button></td>
                    <td>Current Identity: <strong>{{ msgraph.me['userPrincipalName'] }}</strong></td>
                    <td>
                        % if msgraph.photo:
                            <img class="profile-photo" src="data:image/png;base64,{{ msgraph.photo }}">
                        % end
                    </td>
                </tr>
            </table>

        % else:

            <table class="homepage">
                <tr>
                    <td><button type="button" class="btn btn-success btn-md" onclick="window.location.href='/login'">Connect</button></td>
                    <td colspan=2>Click the Connect button and log in to see the last 10 messages in your inbox.</td>
                <tr>
            </table>

        % end

    </div>
    <script src="/static/scripts/jquery-1.10.2.js"></script>
    <script src="/static/scripts/bootstrap.js"></script>
    <script src="/static/scripts/respond.js"></script>
</body>
</html>
