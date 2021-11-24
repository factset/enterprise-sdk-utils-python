class AccessTokenError(Exception):
    """Raise when there's an issue retrieving an access token"""

    pass


class AuthServerMetadataError(Exception):
    """Raise when there is an issue retrieving metadata from the authorization server"""

    pass


class AuthServerMetadataContentError(AuthServerMetadataError):
    """Raise when there is an issue with the authorization server metadata content"""

    pass


class ConfidentialClientError(Exception):
    """Raise for catch-all exceptions"""

    pass


class ConfigurationError(Exception):
    """Raise when Credentials cannot be interrogated"""

    pass


class JWSSigningError(Exception):
    """Raise during any exceptions during signing of the JWS"""

    pass
