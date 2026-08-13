from django.contrib.auth.views import redirect_to_login

# The mitmproxy addon calls the ingest API directly with a shared-secret
# token, not a browser session — it can never log in, so it must stay exempt.
EXEMPT_PREFIXES = ("/api/flows/ingest/", "/api/custom-headers/", "/accounts/login/", "/static/")


class LoginRequiredMiddleware:
    """Require an authenticated session for every view except the ones above.

    This tool captures live traffic (credentials, tokens, etc.) and can
    trigger real outbound requests, so nothing here should be reachable
    without logging in first.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated and not request.path.startswith(EXEMPT_PREFIXES):
            return redirect_to_login(request.get_full_path())
        return self.get_response(request)
