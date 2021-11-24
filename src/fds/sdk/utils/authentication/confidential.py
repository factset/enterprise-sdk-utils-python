import json
import logging
import time
import uuid

import requests
from jose import JWSError, jws
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session

from .constants import CONSTS
from .oauth2client import OAuth2Client
from .exceptions import (
    AccessTokenError,
    ConfidentialClientError,
    ConfigurationError,
    JWSSigningError,
    AuthServerMetadataError,
    AuthServerMetadataContentError,
)

# Set up logger
log = logging.getLogger(__name__)


class ConfidentialClient(OAuth2Client):
    """
    Helper class that supports FactSet's implementation of the OAuth 2.0
    client credentials flow.

    The main purpose of this class is to provide an access token that can
    be used to authenticate against FactSet's APIs. It takes care of fetching
    the access token, caching it and refreshing it as needed.
    """

    def __init__(self, config_path: str = "", config: dict = None) -> None:
        """
        Creates a new ConfidentialClient.

        When setting up the OAuth 2.0 client, this constructor reaches out to
        FactSet's well-known URI to retrieve metadata about its authorization
        server. This information along with information about the OAuth 2.0
        client is stored and used whenever a new access token is fetched.

        Args:
            `NB`: Either `config_path` OR `config` should be sent, not both.

            `config_path` (str) : Path to credentials configuration file.
            `config` (dict) : Dictionary containing authorization credentials.

                `Example config`
                {
                    "name": "Application Name registered with FactSet:Developer",
                    "clientId": "Client ID registered with FactSet:Developer",
                    "clientAuthType": "Confidential",
                    "owners": ["Owner ID(s) of this configuration"],
                    "jwk": {
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": "Key ID",
                        "d": "ECC Private Key",
                        "n": "Modulus",
                        "e": "Exponent",
                        "p": "First Prime Factor",
                        "q": "Second Prime Factor",
                        "dp": "First Factor CRT Exponent",
                        "dq": "Second Factor CRT Exponent",
                        "qi": "First CRT Coefficient",
                    }
                }

                `NB`: Within the JWK parameters kty, alg, use, kid, n, e, d, p, q, dp, dq, qi are required for authorization.
        Raises:
            AuthServerMetadataError: Raised if there's an issue retrieving the authorization server metadata
            AuthServerMetadataContentError: Raised if the authorization server metadata is incomplete
            ConfidentialClientError: Raised if instantiation errors occur
            ConfigurationError: Raised if there's an issue reading the configuration file
            KeyError: Raised if configuration is missing a required property
            ValueError: Raised if `config_path` or `config` are not provided properly
        """

        if not config_path and not config:
            raise ValueError("Either 'config_path' or 'config' must be set.")

        if config_path and config:
            raise ValueError("Either 'config_path' or 'config' must be set.  Not Both.")

        if config_path:
            try:
                with open(config_path, "r") as config_file:
                    self._config = json.load(config_file)
                    log.debug("Retrieved configuration from file: %s", config_path)
            except Exception as e:
                raise ConfigurationError(f"Error retrieving contents of {config_path}") from e

        if config:
            self._config = config

        try:
            self._oauth_session = OAuth2Session(
                client=BackendApplicationClient(client_id=self._config[CONSTS.CONFIG_CLIENT_ID])
            )
        except Exception as e:
            raise ConfidentialClientError(
                f"Error instantiating OAuth2 session with {CONSTS.CONFIG_CLIENT_ID}:{self._config[CONSTS.CONFIG_CLIENT_ID]}"
            ) from e

        log.debug("Reviewing credentials format and completeness")

        self._config.setdefault(CONSTS.CONFIG_WELL_KNOWN_URI, CONSTS.FACTSET_WELL_KNOWN_URI)

        if CONSTS.CONFIG_JWK not in self._config:
            raise KeyError(f"'{CONSTS.CONFIG_JWK}' must be contained within configuration")

        if not set(CONSTS.CONFIG_JWK_REQUIRED_KEYS).issubset(set(self._config[CONSTS.CONFIG_JWK].keys())):
            raise KeyError(f"JWK must contain the following items: '{CONSTS.CONFIG_JWK_REQUIRED_KEYS}'")

        log.debug("Credentials are complete and formatted correctly")

        self._init_auth_server_metadata()

        self._cached_token = {}

    def _init_auth_server_metadata(self) -> None:
        try:
            log.debug(
                "Attempting metadata retrieval from well_known_uri: %s", self._config[CONSTS.CONFIG_WELL_KNOWN_URI]
            )
            res = requests.get(self._config[CONSTS.CONFIG_WELL_KNOWN_URI])
            log.debug("Request from well_known_uri completed with status: %s", res.status_code)
            log.debug("Response headers from well_known_uri were %s", res.headers)
            self._well_known_uri_metadata = res.json()
        except Exception as e:
            raise AuthServerMetadataError(
                f"Error retrieving contents from the well_known_uri: {self._config[CONSTS.CONFIG_WELL_KNOWN_URI]}"
            ) from e

        if (
            CONSTS.META_ISSUER not in self._well_known_uri_metadata
            or CONSTS.META_TOKEN_ENDPOINT not in self._well_known_uri_metadata
        ):
            raise AuthServerMetadataContentError(
                f"Both '{CONSTS.META_ISSUER}' and '{CONSTS.META_TOKEN_ENDPOINT}' are required within contents of well_known_uri: {self._config[CONSTS.CONFIG_WELL_KNOWN_URI]}"
            )
        log.debug(
            "Retrieved issuer: %s and token_endpoint: %s from well_known_uri",
            self._well_known_uri_metadata[CONSTS.META_ISSUER],
            self._well_known_uri_metadata[CONSTS.META_TOKEN_ENDPOINT],
        )

    def _get_client_assertion_jws(self) -> str:
        issued_at = time.time()
        try:
            return jws.sign(
                payload={
                    "sub": self._config[CONSTS.CONFIG_CLIENT_ID],
                    "iss": self._config[CONSTS.CONFIG_CLIENT_ID],
                    "aud": [self._well_known_uri_metadata[CONSTS.META_ISSUER]],
                    "nbf": issued_at - CONSTS.CC_JWT_NOT_BEFORE_SECS,
                    "iat": issued_at,
                    "exp": issued_at + CONSTS.CC_JWT_EXPIRE_AFTER_SECS,
                    "jti": str(uuid.uuid4()),
                },
                key=self._config[CONSTS.CONFIG_JWK],
                algorithm=self._config[CONSTS.CONFIG_JWK][CONSTS.JWK_ALG],
                headers={"kid": self._config[CONSTS.CONFIG_JWK][CONSTS.JWK_KID]},
            )
        except JWSError as je:
            raise JWSSigningError("Error attempting to sign JWS") from je

    def _is_cached_token_valid(self) -> bool:
        if not self._cached_token:
            log.debug("Access Token cache is empty")
            return False
        if time.time() < self._cached_token[CONSTS.TOKEN_EXPIRES_AT]:
            return True
        else:
            log.debug("Cached access token has expired at %s", self._cached_token[CONSTS.TOKEN_EXPIRES_AT])
            return False

    def get_access_token(self) -> str:
        """
        Returns an access token that can be used for authentication.

        If the cache contains a valid access token, it's returned. Otherwise
        a new access token is retrieved from FactSet's authorization server.

        The access token should be used immediately and not stored to avoid
        any issues with token expiry.

        The access token is used in the Authorization header when when accessing
        FactSet's APIs. Example: `{"Authorization": "Bearer access-token"}`

        Returns:
            str: access token for protected resource requests

        Raises:
            AccessTokenError: Raised if there's an issue retrieving the access token
            JWSSigningError: Raised if there's an issue signing the JWS
        """
        if self._is_cached_token_valid():
            log.debug(
                "Retrieving cached token. Expires in '%s' seconds.",
                int(self._cached_token[CONSTS.TOKEN_EXPIRES_AT] - time.time()),
            )
            return self._cached_token[CONSTS.TOKEN_ACCESS_TOKEN]

        try:
            log.debug("Fetching new access token")
            token = self._oauth_session.fetch_token(
                token_url=self._well_known_uri_metadata[CONSTS.META_TOKEN_ENDPOINT],
                client_id=self._config[CONSTS.CONFIG_CLIENT_ID],
                client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion=self._get_client_assertion_jws(),
            )
            self._cached_token = token
            log.info("Caching token that expires at %s", token[CONSTS.TOKEN_EXPIRES_AT])
            return token[CONSTS.TOKEN_ACCESS_TOKEN]
        except Exception as e:
            raise AccessTokenError("Error attempting to get access token") from e
