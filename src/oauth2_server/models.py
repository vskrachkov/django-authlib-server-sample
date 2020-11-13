import time

from authlib.oauth2.rfc6749 import ClientMixin, TokenMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.utils.crypto import get_random_string
from django.conf import settings

CLIENT_ID_LENGTH = 32
CLIENT_SECRET_LENGTH = 48

DEFAULT_TOKEN_EXPIRATION_SECONDS = 3600

GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_IMPLICIT = "implicit"
GRANT_PASSWORD = "password"
GRANT_CLIENT_CREDENTIALS = "client_credentials"

GRANT_CHOICES = (
    (GRANT_AUTHORIZATION_CODE, GRANT_AUTHORIZATION_CODE),
    (GRANT_IMPLICIT, GRANT_IMPLICIT),
    (GRANT_PASSWORD, GRANT_PASSWORD),
    (GRANT_CLIENT_CREDENTIALS, GRANT_CLIENT_CREDENTIALS),
)

RESPONSE_TYPE_CODE = "code"
RESPONSE_TYPE_TOKEN = "token"

RESPONSE_TYPE_CHOICES = (
    (RESPONSE_TYPE_CODE, RESPONSE_TYPE_CODE),
    (RESPONSE_TYPE_TOKEN, RESPONSE_TYPE_TOKEN),
)


def generate_client_id():
    return get_random_string(
        length=CLIENT_ID_LENGTH,
        allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    )


def generate_client_secret():
    return get_random_string(
        length=CLIENT_SECRET_LENGTH,
        allowed_chars=(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!#$*()[]{}"
        ),
    )


def access_token_generator(
    client: ClientMixin, grant_type: str, user: AbstractBaseUser, scope: str
) -> str:
    raise NotImplementedError()


def refresh_token_generator(
    client: ClientMixin, grant_type: str, user: AbstractBaseUser, scope: str
) -> str:
    raise NotImplementedError()


def expires_generator(client: ClientMixin, grant_type: str) -> int:
    return DEFAULT_TOKEN_EXPIRATION_SECONDS


class OAuth2Client(models.Model, ClientMixin):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    client_id = models.CharField(
        max_length=CLIENT_ID_LENGTH,
        unique=True,
        db_index=True,
        default=generate_client_id,
    )
    client_secret = models.CharField(
        max_length=CLIENT_SECRET_LENGTH, default=generate_client_secret
    )
    client_name = models.CharField(max_length=120)
    scope = models.TextField()
    response_type = models.CharField(
        max_length=100, choices=RESPONSE_TYPE_CHOICES, default=RESPONSE_TYPE_CODE
    )
    grand_type = models.CharField(
        max_length=100, choices=GRANT_CHOICES, default=GRANT_AUTHORIZATION_CODE
    )
    token_endpoint_auth_method = models.CharField(max_length=120, default="")

    def get_client_id(self) -> str:
        return self.client_id

    def get_default_redirect_uri(self) -> str:
        return ""

    def get_allowed_scope(self, scope: str) -> str:
        allowed = set(self.scope.strip().split())
        requested = set(scope.strip().split())
        return " ".join(requested & allowed)

    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return self.redirect_uris.filter(redirect_uri=redirect_uri).exists()

    def has_client_secret(self) -> bool:
        return bool(self.client_secret)

    def check_client_secret(self, client_secret: str) -> bool:
        return self.client_secret == client_secret

    def check_token_endpoint_auth_method(self, method: str) -> bool:
        return self.token_endpoint_auth_method == method

    def check_response_type(self, response_type: str) -> bool:
        return self.response_type == response_type

    def check_grant_type(self, grant_type: str) -> bool:
        return self.grand_type == grant_type


class OAuth2ClientRedirectURI(models.Model):
    client = models.ForeignKey(
        OAuth2Client,
        on_delete=models.CASCADE,
        related_name="redirect_uris",
        related_query_name="redirect_uri",
    )
    redirect_uri = models.CharField(max_length=512)


def now_timestamp():
    return int(time.time())


class OAuth2Token(models.Model, TokenMixin):
    client = models.ForeignKey(
        OAuth2Client,
        on_delete=models.CASCADE,
        related_name="tokens",
        related_query_name="token",
    )
    access_token = models.CharField(max_length=255, unique=True)
    refresh_token = models.CharField(max_length=255, blank=True, null=True)
    scope = models.TextField()
    issued_at = models.IntegerField(null=False, default=now_timestamp)
    expires_in = models.IntegerField(
        null=False, default=DEFAULT_TOKEN_EXPIRATION_SECONDS
    )

    @classmethod
    def new(cls, client: OAuth2Client, **kw) -> "OAuth2Token":
        print(f"token: kwargs: {kw}")
        token = cls()
        token.client = client
        token.access_token = get_random_string(100)
        token.refresh_token = get_random_string(100)
        token.scope = kw.get('scope', '')
        if kw.get('expires_in'):
            token.expires_in = kw.get('expires_in')
        token.save(force_insert=True)
        return token

    def get_client_id(self) -> str:
        return self.client.client_id

    def get_scope(self) -> str:
        return self.scope

    def get_expires_in(self) -> int:
        return self.expires_in

    def get_expires_at(self) -> int:
        return self.issued_at + self.expires_in
