from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from oauth2_server.oauth2 import server


def is_user_confirmed(request: HttpRequest) -> bool:
    return True


@require_http_methods(["GET", "POST"])
def authorize(request: HttpRequest) -> HttpResponse:
    if request.method == "GET":
        grant = server.get_consent_grant(request)
        context = dict(grant=grant, user=request.user)
        return render(request, "oauth2_server/authorize.html", context)

    if is_user_confirmed(request):
        # granted by resource owner
        return server.create_authorization_response(request, grant_user=request.user)

    # denied by resource owner
    return server.create_authorization_response(request, grant_user=None)


@require_http_methods(["POST"])  # we only allow POST for token endpoint
def issue_token(request: HttpRequest) -> HttpResponse:
    return server.create_token_response(request)
