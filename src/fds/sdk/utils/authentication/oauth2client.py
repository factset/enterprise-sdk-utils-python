from abc import ABC, abstractmethod


class OAuth2Client(ABC):
    """
    Abstract base class for OAuth 2.0 clients.
    """

    @abstractmethod
    def get_access_token(self) -> str:
        """
        Retrieve Access Token
        Returns:
            str: access token for protected resource requests
        """
        pass
