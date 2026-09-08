class AccessTokenError(Exception):
    """Raise when there's an issue retrieving an access token"""


class AuthServerMetadataError(Exception):
    """Raise when there is an issue retrieving metadata from the authorization server"""


class AuthServerMetadataContentError(AuthServerMetadataError):
    """Raise when there is an issue with the authorization server metadata content"""


class ConfidentialClientError(Exception):
    """Raise for catch-all exceptions"""


class ConfigurationError(Exception):
    """Raise when Credentials cannot be interrogated"""


class JWSSigningError(Exception):
    """Raise during any exceptions during signing of the JWS"""
