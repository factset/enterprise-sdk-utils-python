import json
import logging
import platform
from unittest.mock import ANY, mock_open

import pytest

from fds.sdk.utils.authentication import (
    AccessTokenError,
    AuthServerMetadataError,
    AuthServerMetadataContentError,
    ConfidentialClient,
    ConfidentialClientError,
    ConfigurationError,
    OAuth2Client,
)


@pytest.fixture()
def example_config():
    return {
        "name": "ExampleApp",
        "clientId": "test-clientid",
        "clientAuthType": "Confidential",
        "owners": ["owner_id"],
        "jwk": {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "jwk_kid",
            "d": "d",
            "n": "n",
            "e": "e",
            "p": "p",
            "q": "q",
            "dp": "dp",
            "dq": "dq",
            "qi": "qi",
        },
    }


@pytest.fixture()
def client(mocker, example_config):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test-token", "expires_at": 10},
    )

    mock_get = mocker.patch("requests.Session.get")
    mock_get.return_value.json.return_value = {
        "issuer": "test-issuer",
        "token_endpoint": "https://test.token.endpoint",
    }

    mocker.patch("joserfc.jwk.RSAKey.import_key", return_value="jwk")

    return ConfidentialClient(config=example_config)


def test_confidential_client_inheritance(client):
    assert issubclass(ConfidentialClient, OAuth2Client)
    assert isinstance(client, OAuth2Client)


def test_constructor_with_config(mocker, example_config, caplog):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )

    class AuthServerMetadataRes:
        status_code = 200
        headers = {"header": "value"}

        def json(self):
            return {"issuer": "test", "token_endpoint": "http://test.test"}

    caplog.set_level(logging.DEBUG)
    mocker.patch("requests.Session.get", return_value=AuthServerMetadataRes())

    client = ConfidentialClient(config=example_config)

    assert client

    assert "Credentials are complete" in caplog.text
    assert "Attempting metadata retrieval" in caplog.text
    assert "Request from well_known_uri completed with status: 200" in caplog.text
    assert "headers from well_known_uri" in caplog.text
    assert "Retrieved issuer" in caplog.text
    assert "and token_endpoint" in caplog.text


def test_constructor_with_file(mocker, example_config, caplog):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )

    class AuthServerMetadataRes:
        status_code = 200
        headers = {"header": "value"}

        def json(self):
            return {"issuer": "test", "token_endpoint": "http://test.test"}

    caplog.set_level(logging.DEBUG)
    mocker.patch("requests.Session.get", return_value=AuthServerMetadataRes())
    mocker.patch("json.load", return_value=example_config)
    fake_file_path = "/my/fake/path/creds.json"

    mocked_open = mocker.patch(
        "fds.sdk.utils.authentication.confidential.open", mock_open(read_data=json.dumps(example_config))
    )
    client = ConfidentialClient(fake_file_path)

    assert client

    mocked_open.assert_called_once_with(fake_file_path, "r")
    assert "Attempting metadata retrieval" in caplog.text
    assert "Request from well_known_uri completed with status: 200" in caplog.text
    assert "headers from well_known_uri" in caplog.text
    assert "Retrieved issuer" in caplog.text
    assert "and token_endpoint" in caplog.text


def test_constructor_bad_params():
    with pytest.raises(ValueError):
        ConfidentialClient()

    with pytest.raises(ValueError):
        ConfidentialClient(config_path="my_path", config=example_config)

    with pytest.raises(ValueError):
        ConfidentialClient(config={})

    with pytest.raises(ValueError):
        ConfidentialClient("")


def test_constructor_with_bad_file():
    with pytest.raises(ConfigurationError):
        ConfidentialClient("/my/fake/file/path")


def test_constructor_bad_session_instantiation(mocker, example_config):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch("fds.sdk.utils.authentication.confidential.OAuth2Session", side_effect=Exception("fail!"))

    with pytest.raises(ConfidentialClientError):
        ConfidentialClient(config=example_config)


def test_constructor_session_instantiation(mocker, example_config):
    test_client_id = "good_test"
    backend_result = "good_mock_backend"
    example_config["clientId"] = test_client_id
    mock_oauth_backend = mocker.patch(
        "fds.sdk.utils.authentication.confidential.BackendApplicationClient", return_value=backend_result
    )

    mock_oauth2_session = mocker.patch("fds.sdk.utils.authentication.confidential.OAuth2Session")

    ConfidentialClient(config=example_config)

    mock_oauth_backend.assert_called_with(client_id=test_client_id)
    mock_oauth2_session.assert_called_with(client=backend_result)


def test_constructor_session_instantiation_with_additional_parameters(mocker, example_config):
    test_client_id = "good_test"
    backend_result = "good_mock_backend"
    example_config["clientId"] = test_client_id
    mock_oauth_backend = mocker.patch(
        "fds.sdk.utils.authentication.confidential.BackendApplicationClient", return_value=backend_result
    )

    mock_oauth2_session = mocker.patch("fds.sdk.utils.authentication.confidential.OAuth2Session")

    additional_parameters = {
        "proxy": "http://my:pass@test.test.test",
        "verify_ssl": False,
        "proxy_headers": {},
    }

    class AuthServerMetadataRes:
        status_code = 200
        headers = {"header": "value"}

        def json(self):
            return {"issuer": "test", "token_endpoint": "http://test.test"}

    get_mock = mocker.patch("requests.Session.get", return_value=AuthServerMetadataRes())

    ConfidentialClient(config=example_config, **additional_parameters)

    mock_oauth_backend.assert_called_with(client_id=test_client_id)
    mock_oauth2_session.assert_called_with(client=backend_result)
    get_mock.assert_called_with(
        url="https://auth.factset.com/.well-known/openid-configuration",
        proxies={"http": "http://my:pass@test.test.test", "https": "http://my:pass@test.test.test"},
        verify=False,
        headers={f"User-Agent": f"fds-sdk/python/utils/1.1.2 ({platform}; Python {platform.python_version()})"},
    )


def test_constructor_custom_well_known_uri(mocker, example_config, caplog):
    caplog.set_level(logging.DEBUG)
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )

    class AuthServerMetadataRes:
        status_code = 200
        headers = {"header": "value"}

        def json(self):
            return {"issuer": "test", "token_endpoint": "http://test.test"}

    get_mock = mocker.patch("requests.Session.get", return_value=AuthServerMetadataRes())
    auth_test = "https://auth.test"

    example_config["wellKnownUri"] = auth_test

    client = ConfidentialClient(config=example_config)

    get_mock.assert_called_with(
        url=auth_test,
        proxies=None,
        verify=True,
        headers={f'User-Agent": "fds-sdk/python/utils/1.1.2 ({platform.system()}; Python {platform.python_version()})'},
    )
    assert client

    assert "Attempting metadata retrieval from well_known_uri: https://auth.test" in caplog.text


def test_constructor_metadata_error(mocker, example_config):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )
    mocker.patch("requests.Session.get", side_effect=Exception("error"))
    with pytest.raises(AuthServerMetadataError):
        ConfidentialClient(config=example_config)


def test_constructor_missing_metadata(mocker, example_config):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )

    class AuthServerMetadataRes:
        status_code = 200
        headers = {"header": "value"}

        @staticmethod
        def json():
            return {}

    mocker.patch("requests.Session.get", return_value=AuthServerMetadataRes)

    with pytest.raises(AuthServerMetadataContentError):
        ConfidentialClient(config=example_config)


def test_missing_jwk(mocker, example_config):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )
    del example_config["jwk"]

    with pytest.raises(KeyError):
        ConfidentialClient(config=example_config)


def test_missing_jwk_data(mocker, example_config):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )
    del example_config["jwk"]["p"]

    with pytest.raises(KeyError):
        ConfidentialClient(config=example_config)


def test_get_access_token(client, mocker, caplog):
    caplog.set_level(logging.INFO)
    mocker.patch("joserfc.jwt.encode", return_value="jws")

    assert client.get_access_token() == "test-token"

    assert "Caching token that expires at" in caplog.text


def test_get_access_token_jws_sign(client, example_config, mocker):
    mocker.patch("fds.sdk.utils.authentication.confidential.time.time", return_value=0)
    mocker.patch("fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_NOT_BEFORE_SECS", 1000)
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_EXPIRE_AFTER_SECS",
        2000,
    )
    mocker.patch("fds.sdk.utils.authentication.confidential.uuid.uuid4", return_value="uuid")
    mock_jws_sign = mocker.patch("joserfc.jwt.encode", return_value="jws")

    client.get_access_token()

    mock_jws_sign.assert_called_once_with(
        claims={
            "sub": "test-clientid",
            "iss": "test-clientid",
            "aud": ["test-issuer"],
            "nbf": -1000,
            "iat": 0,
            "exp": 2000,
            "jti": "uuid",
        },
        key="jwk",
        header={"kid": "jwk_kid", "alg": "RS256"},
    )


def test_get_access_token_jws_sign_error(client, mocker, caplog):
    mocker.patch("fds.sdk.utils.authentication.confidential.time.time", return_value=0)
    mocker.patch("fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_NOT_BEFORE_SECS", 1000)
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_EXPIRE_AFTER_SECS",
        2000,
    )
    mocker.patch("fds.sdk.utils.authentication.confidential.uuid.uuid4", return_value="uuid")

    mocker.patch(
        "joserfc.jwt.encode",
        side_effect=Exception("fail!"),
    )

    with pytest.raises(AccessTokenError):
        client.get_access_token()


def test_get_access_token_fetch(client, mocker):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mock_oauth2_session = mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )
    mocker.patch("fds.sdk.utils.authentication.confidential.time.time", return_value=0)
    mocker.patch("fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_NOT_BEFORE_SECS", 1000)
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_EXPIRE_AFTER_SECS",
        2000,
    )
    mocker.patch("fds.sdk.utils.authentication.confidential.uuid.uuid4", return_value="uuid")
    mocker.patch("joserfc.jwt.encode", return_value="jws")
    mocker.patch("joserfc.jwk.RSAKey.import_key", return_value="jwk")

    client.get_access_token()

    mock_oauth2_session.assert_called_once_with(
        token_url="https://test.token.endpoint",
        client_id="test-clientid",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion="jws",
        proxies=None,
        verify=True,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "User-Agent": f"fds-sdk/python/utils/1.1.2 ({platform.system()}; Python {platform.python_version()})",
        },
    )


def test_get_access_token_fetch_error(client, mocker, caplog):
    caplog.set_level(logging.DEBUG)
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch("fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token", side_effect=Exception("fail!"))
    mocker.patch("fds.sdk.utils.authentication.confidential.time.time", return_value=0)
    mocker.patch("fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_NOT_BEFORE_SECS", 1000)
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.CONSTS.CC_JWT_EXPIRE_AFTER_SECS",
        2000,
    )
    mocker.patch("fds.sdk.utils.authentication.confidential.uuid.uuid4", return_value="uuid")
    mocker.patch("joserfc.jwt.encode", return_value="jws")
    mocker.patch("joserfc.jwk.RSAKey.import_key", return_value="jwk")

    with pytest.raises(AccessTokenError):
        client.get_access_token()

    assert "Access Token cache is empty" in caplog.text


def test_get_access_token_cached(example_config, mocker, caplog):
    caplog.set_level(logging.DEBUG)
    mock_get = mocker.patch("requests.Session.get")
    mock_get.return_value.json.return_value = {
        "issuer": "test-issuer",
        "token_endpoint": "https://test.token.endpoint",
    }
    mocker.patch("joserfc.jwt.encode", return_value="jws")
    mocker.patch("joserfc.jwk.RSAKey.import_key", return_value="jwk")
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mock_oauth2_session = mocker.patch("fds.sdk.utils.authentication.confidential.OAuth2Session")
    mock_oauth2_session.return_value.fetch_token.return_value = {
        "access_token": "test",
        "expires_at": 10,
    }
    mocker.patch("fds.sdk.utils.authentication.confidential.time.time", return_value=0)

    client = ConfidentialClient(config=example_config)

    assert client.get_access_token() == client.get_access_token()
    mock_oauth2_session.return_value.fetch_token.assert_called_once()

    assert "Retrieving cached token. Expires in '10' seconds" in caplog.text


def test_get_access_token_cache_expired(client, mocker, caplog):
    caplog.set_level(logging.DEBUG)
    mocker.patch("joserfc.jwt.encode", return_value="jws")
    mock_oauth2_session = mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={
            "access_token": "test",
            "expires_at": 10,
        },
    )

    mocker.patch("fds.sdk.utils.authentication.confidential.time.time", return_value=20)

    client.get_access_token()
    client.get_access_token()

    assert mock_oauth2_session.call_count == 2

    assert "Cached access token has expired" in caplog.text
