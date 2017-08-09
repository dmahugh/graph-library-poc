"""Microsoft Graph API library

Lightweight alternative to auto-generated .NET-style object model SDK for Python"""
from .connect import UserConnect, AppConnect
from .apphelpers import placeholder
from .userhelpers import contacts, messages, openext, sendmail

__version__ = 'alpha'

__all__ = [
    'contacts',
    'messages',
    'openext',
    'sendmail',
    'AppConnect',
    'UserConnect',
]
