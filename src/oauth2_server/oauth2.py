from authlib.integrations.django_oauth2 import AuthorizationServer
from authlib.oauth2 import HttpRequest
from authlib.oauth2.rfc6749 import TokenMixin
from authlib.oauth2.rfc6750 import BearerToken
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata

from oauth2_server.models import (
    OAuth2Client,
    OAuth2Token,
    expires_generator,
    refresh_token_generator,
    access_token_generator,
)


class MyAuthorizationServer(AuthorizationServer):
    def save_oauth2_token(self, token: dict, request: HttpRequest) -> TokenMixin:
        return OAuth2Token.new(request.client, **token)


server: AuthorizationServer = MyAuthorizationServer(
    client_model=OAuth2Client,
    token_model=OAuth2Token,
    generate_token=BearerToken(
        access_token_generator=access_token_generator,
        refresh_token_generator=refresh_token_generator,
        expires_generator=expires_generator,
    ),
    metadata=AuthorizationServerMetadata({}),
)
