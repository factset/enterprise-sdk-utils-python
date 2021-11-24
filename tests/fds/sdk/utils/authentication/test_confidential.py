import json
import logging
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
    mock_get = mocker.patch("fds.sdk.utils.authentication.confidential.requests.get")
    mock_get.return_value.json.return_value = {
        "issuer": "test-issuer",
        "token_endpoint": "https://test.token.endpoint",
    }

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
    mocker.patch("requests.get", return_value=AuthServerMetadataRes())

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
    mocker.patch("requests.get", return_value=AuthServerMetadataRes())
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

    get_mock = mocker.patch("requests.get", return_value=AuthServerMetadataRes())
    auth_test = "https://auth.test"

    example_config["wellKnownUri"] = auth_test

    client = ConfidentialClient(config=example_config)

    get_mock.assert_called_with(auth_test)
    assert client

    assert "Attempting metadata retrieval from well_known_uri: https://auth.test" in caplog.text


def test_constructor_metadata_error(mocker, example_config):
    mocker.patch("fds.sdk.utils.authentication.confidential.BackendApplicationClient")
    mocker.patch(
        "fds.sdk.utils.authentication.confidential.OAuth2Session.fetch_token",
        return_value={"access_token": "test", "expires_at": 10},
    )
    mocker.patch("requests.get", side_effect=Exception("error"))
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

        def json():
            return {}

    mocker.patch("requests.get", return_value=AuthServerMetadataRes)

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
    mocker.patch("fds.sdk.utils.authentication.confidential.jws.sign", return_value="jws")

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
    mock_jws_sign = mocker.patch("fds.sdk.utils.authentication.confidential.jws.sign", return_value="jws")

    client.get_access_token()

    mock_jws_sign.assert_called_once_with(
        payload={
            "sub": "test-clientid",
            "iss": "test-clientid",
            "aud": ["test-issuer"],
            "nbf": -1000,
            "iat": 0,
            "exp": 2000,
            "jti": "uuid",
        },
        key=example_config["jwk"],
        algorithm="RS256",
        headers={"kid": "jwk_kid"},
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
        "fds.sdk.utils.authentication.confidential.jws.sign",
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
    mocker.patch("fds.sdk.utils.authentication.confidential.jws.sign", return_value="jws")

    client.get_access_token()

    mock_oauth2_session.assert_called_once_with(
        token_url="https://test.token.endpoint",
        client_id="test-clientid",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion="jws",
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
    mocker.patch("fds.sdk.utils.authentication.confidential.jws.sign", return_value="jws")

    with pytest.raises(AccessTokenError):
        client.get_access_token()

    assert "Access Token cache is empty" in caplog.text


def test_get_access_token_cached(example_config, mocker, caplog):
    caplog.set_level(logging.DEBUG)
    mock_get = mocker.patch("fds.sdk.utils.authentication.confidential.requests.get")
    mock_get.return_value.json.return_value = {
        "issuer": "test-issuer",
        "token_endpoint": "https://test.token.endpoint",
    }
    mocker.patch("fds.sdk.utils.authentication.confidential.jws.sign", return_value="jws")
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
    mocker.patch("fds.sdk.utils.authentication.confidential.jws.sign", return_value="jws")
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
