import platform


class CONSTS:
    # confidential client assertion JWT
    CC_JWT_NOT_BEFORE_SECS = 5
    CC_JWT_EXPIRE_AFTER_SECS = 300

    # JSON Web Key
    JWK_ALG = "alg"
    JWK_KID = "kid"

    # auth server metadata
    META_ISSUER = "issuer"
    META_TOKEN_ENDPOINT = "token_endpoint"

    # access token
    TOKEN_ACCESS_TOKEN = "access_token"
    TOKEN_EXPIRES_AT = "expires_at"
    TOKEN_EXPIRY_OFFSET_SECS = 30

    # config
    CONFIG_CLIENT_ID = "clientId"
    CONFIG_WELL_KNOWN_URI = "wellKnownUri"
    CONFIG_JWK = "jwk"
    CONFIG_JWK_REQUIRED_KEYS = ["kty", "alg", "use", "kid", "n", "e", "d", "p", "q", "dp", "dq", "qi"]

    # default values
    FACTSET_WELL_KNOWN_URI = "https://auth.factset.com/.well-known/openid-configuration"

    USER_AGENT = f"fds-sdk/python/utils/2.1.2 ({platform.system()}; Python {platform.python_version()})"


CONSTS = CONSTS()
