from typing import Type
import pytest
from fds.sdk.utils.authentication import OAuth2Client


def test_cannot_instantiate():
    with pytest.raises(TypeError):
        OAuth2Client()


def test_bad_instantiation():
    class bad_class(OAuth2Client):
        pass

    with pytest.raises(TypeError):
        bad_class()


def test_good_instantiation():
    ret_val = "good_token"

    class good_class(OAuth2Client):
        def get_access_token(self):
            return ret_val

    my_good_instance = good_class()
    assert callable(my_good_instance.get_access_token)
    assert issubclass(good_class, OAuth2Client)
    assert isinstance(my_good_instance, OAuth2Client)
