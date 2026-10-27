"""Unit tests for the SEB auth module (HTTP mocked)."""
from __future__ import annotations

import base64
import json
import time

import pytest

from rowxplorer_lib.exceptions import AuthenticationError
from rowxplorer_lib.seb_auth import (
    DEFAULT_CLIENT_ID,
    IamCredentials,
    SebAuth,
    SebAuthConfig,
    SebTokens,
    _jwt_exp,
    _parse_expiration,
)


def make_jwt(exp: int) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=").decode()
    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"exp": exp, "iss": "https://account.groupeseb.com"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.signature"


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None, headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text if text is not None else json.dumps(self._payload)
        self.headers = headers or {}
        self.ok = 200 <= status_code < 300

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError("not json")
        return self._payload


class FakeSession:
    """Returns queued responses in call order; records every call."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.headers = {}
        self.calls = []

    def _next(self):
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0] if self.responses else FakeResponse()

    def get(self, url, **kw):
        self.calls.append({"method": "GET", "url": url, **kw})
        return self._next()

    def post(self, url, **kw):
        self.calls.append({"method": "POST", "url": url, **kw})
        return self._next()


# -- refresh ---------------------------------------------------------------------


def test_refresh_posts_correct_params_and_parses_tokens():
    exp = int(time.time()) + 120
    id_token = make_jwt(exp)
    sess = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "access_token": "AT",
                    "id_token": id_token,
                    "scope": "full refresh_token openid",
                    "token_type": "Bearer",
                },
            )
        ]
    )
    cfg = SebAuthConfig(refresh_token="REFRESH123")
    auth = SebAuth(cfg, session=sess)
    tokens = auth.refresh()
    assert tokens.access_token == "AT"
    assert tokens.id_token == id_token
    assert tokens.expires_at == exp
    assert tokens.expired is False
    call = sess.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://account.groupeseb.com/services/oauth2/token"
    assert call["params"]["grant_type"] == "refresh_token"
    assert call["params"]["client_id"] == DEFAULT_CLIENT_ID
    assert call["params"]["refresh_token"] == "REFRESH123"


def test_refresh_without_token_raises():
    auth = SebAuth(SebAuthConfig(), session=FakeSession())
    with pytest.raises(AuthenticationError):
        auth.refresh()


def test_refresh_http_error_raises():
    sess = FakeSession([FakeResponse(400, {"error": "invalid_grant"})])
    auth = SebAuth(SebAuthConfig(refresh_token="R"), session=sess)
    with pytest.raises(AuthenticationError, match="invalid_grant"):
        auth.refresh()


# -- id_token caching ---------------------------------------------------------------


def test_id_token_cached_when_fresh():
    sess = FakeSession()
    auth = SebAuth(SebAuthConfig(refresh_token="R"), session=sess)
    auth._tokens = SebTokens(
        access_token="AT", id_token="IDTOK", expires_at=time.time() + 100
    )
    assert auth.id_token() == "IDTOK"
    assert sess.calls == []


def test_id_token_refreshes_when_expired():
    fresh = make_jwt(int(time.time()) + 120)
    sess = FakeSession([FakeResponse(200, {"access_token": "AT", "id_token": fresh})])
    auth = SebAuth(SebAuthConfig(refresh_token="R"), session=sess)
    auth._tokens = SebTokens(
        access_token="OLD", id_token="OLDID", expires_at=time.time() - 10
    )
    assert auth.id_token() == fresh
    assert len(sess.calls) == 1


# -- Cognito --------------------------------------------------------------------------


def test_cognito_credentials_full_flow():
    exp = int(time.time()) + 120
    id_token = make_jwt(exp)
    iam_exp = time.time() + 3600
    sess = FakeSession(
        [
            FakeResponse(200, {"IdentityId": "eu-west-1:abc-123"}),
            FakeResponse(200, {"IdentityId": "eu-west-1:abc-123", "Token": "OPENIDJWT"}),
            FakeResponse(
                200,
                {
                    "IdentityId": "eu-west-1:abc-123",
                    "Credentials": {
                        "AccessKeyId": "AK",
                        "SecretKey": "SK",
                        "SessionToken": "ST",
                        "Expiration": iam_exp,
                    },
                },
            ),
        ]
    )
    cfg = SebAuthConfig(refresh_token="R")
    auth = SebAuth(cfg, session=sess)
    auth._tokens = SebTokens(access_token="AT", id_token=id_token, expires_at=exp)
    creds = auth.cognito_credentials()
    assert creds.access_key_id == "AK"
    assert creds.secret_key == "SK"
    assert creds.session_token == "ST"
    assert creds.expiration == pytest.approx(iam_exp)
    # three calls, in order, against the proxy
    assert len(sess.calls) == 3
    get_id, get_open, get_creds = sess.calls
    for call in sess.calls:
        assert call["url"] == "https://consumers.api.groupe-seb.com"
        assert call["headers"]["Content-Type"] == "application/x-amz-json-1.1"
    assert get_id["headers"]["X-Amz-Target"] == "AWSCognitoIdentityService.GetId"
    assert get_id["json"]["IdentityPoolId"] == cfg.cognito_pool_id
    # provider key = host only (no scheme)
    assert get_id["json"]["Logins"] == {"account.groupeseb.com": id_token}
    assert get_open["headers"]["X-Amz-Target"] == "AWSCognitoIdentityService.GetOpenIdToken"
    assert get_open["json"]["IdentityId"] == "eu-west-1:abc-123"
    assert get_creds["headers"]["X-Amz-Target"] == (
        "AWSCognitoIdentityService.GetCredentialsForIdentity"
    )
    assert get_creds["json"]["Logins"] == {"cognito-identity.amazonaws.com": "OPENIDJWT"}


def test_cognito_credentials_cached():
    exp = int(time.time()) + 120
    id_token = make_jwt(exp)
    sess = FakeSession(
        [
            FakeResponse(200, {"IdentityId": "eu-west-1:abc-123"}),
            FakeResponse(200, {"IdentityId": "eu-west-1:abc-123", "Token": "OPENIDJWT"}),
            FakeResponse(
                200,
                {
                    "Credentials": {
                        "AccessKeyId": "AK",
                        "SecretKey": "SK",
                        "SessionToken": "ST",
                        "Expiration": time.time() + 3600,
                    }
                },
            ),
        ]
    )
    auth = SebAuth(SebAuthConfig(refresh_token="R"), session=sess)
    auth._tokens = SebTokens(access_token="AT", id_token=id_token, expires_at=exp)
    first = auth.cognito_credentials()
    second = auth.cognito_credentials()
    assert first is second
    assert len(sess.calls) == 3  # no extra calls on the second access


def test_cognito_error_raises():
    sess = FakeSession(
        [
            FakeResponse(
                400,
                {"__type": "NotAuthorizedException", "message": "bad token"},
            )
        ]
    )
    auth = SebAuth(SebAuthConfig(refresh_token="R"), session=sess)
    auth._tokens = SebTokens(
        access_token="AT", id_token="x", expires_at=time.time() + 100
    )
    with pytest.raises(AuthenticationError, match="NotAuthorizedException"):
        auth.cognito_credentials()


# -- login (full OAuth chain) -------------------------------------------------------------


AUTHORIZE_URL = (
    "https://account.groupeseb.com/services/oauth2/authorize/expid_x"
    "?client_id=CID&redirect_uri=gsmoduser%3A%2F%2Ftokens"
    "&response_type=token+id_token+refresh_token&state=STATE&nonce=NONCE&version=10.0.0"
)
RAAP_A = "https://account.groupeseb.com/setup/secur/RemoteAccessAuthorizationPage.apexp?source=AAA"
LOGIN_URL = "https://account.groupeseb.com/Login?startURL=x"
FRONTDOOR = "https://account.groupeseb.com/secur/frontdoor.jsp?sid=1&retURL=x"
LOGINFLOW = "https://account.groupeseb.com/apex/LoginFlow?retURL=x"
RAAP_B = "https://account.groupeseb.com/setup/secur/RemoteAccessAuthorizationPage.apexp?source=BBB"

CONTINUATION_HTML = (
    "<html><body><script>window.location.replace('" + AUTHORIZE_URL + "');</script></body></html>"
)
LOGIN_HTML = """
<html><body>
<form id="LoginPage:j_id4" name="LoginPage:j_id4" method="post"
      action="/Login?sfdcIFrameOrigin=null" enctype="application/x-www-form-urlencoded">
<input type="hidden" name="LoginPage:j_id4" value="LoginPage:j_id4" />
<input type="hidden" name="com.salesforce.visualforce.ViewState" value="VS123" />
<input type="hidden" name="com.salesforce.visualforce.ViewStateVersion" value="V1" />
<input type="hidden" name="com.salesforce.visualforce.ViewStateMAC" value="MAC1" />
</form>
<script>loginAF=function(userEmail,password){A4J.AJAX.Submit('LoginPage:j_id4',null,
{'similarityGroupingId':'LoginPage:j_id4:j_id59','oncomplete':function(){},
'parameters':{'password':password,'userEmail':userEmail,
'LoginPage:j_id4:j_id59':'LoginPage:j_id4:j_id59'}})};</script>
</body></html>
"""
FRONTDOOR_HTML = (
    "<html><body><script>window.location.replace('" + LOGINFLOW + "');</script></body></html>"
)
LOGINFLOW_HTML = """
<html><body>
<form id="LoginFlow:j_id5" name="LoginFlow:j_id5" method="post"
      action="/LoginFlow?sfdcIFrameOrigin=null" enctype="application/x-www-form-urlencoded">
<input type="hidden" name="LoginFlow:j_id5" value="LoginFlow:j_id5" />
<input type="hidden" name="com.salesforce.visualforce.ViewState" value="VS456" />
</form>
<script>
function finishLoginFlowAndRedirectJS(){A4J.AJAX.Submit('LoginFlow:j_id5',null,
{'similarityGroupingId':'LoginFlow:j_id5:j_id6','oncomplete':function(){},
'parameters':{'LoginFlow:j_id5:j_id6':'LoginFlow:j_id5:j_id6'}});}
window.onload=function(){finishLoginFlowAndRedirectJS();};
</script>
</body></html>
"""


def _a4j_redirect_xml(location: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<partial-response><changes><change><data>redirect</data></change></changes>'
        '<meta name="Ajax-Response" content="redirect"/>'
        f'<meta name="Location" content="{location}"/>'
        "</partial-response>"
    )


def test_login_full_flow():
    exp = int(time.time()) + 120
    id_token = make_jwt(exp)
    tokens_url = (
        "gsmoduser://tokens#access_token=AT&id_token="
        + id_token
        + "&refresh_token=REFRESHNEW&state=STATE"
        "&scope=full+refresh_token+openid&token_type=Bearer"
    )
    raap_html = (
        "<html><body><script>window.location.replace('"
        + tokens_url
        + "');</script></body></html>"
    )
    sess = FakeSession(
        [
            FakeResponse(200, text=CONTINUATION_HTML),  # 1 ContinuationForExpId
            FakeResponse(302, headers={"Location": RAAP_A}),  # 2 authorize
            FakeResponse(302, headers={"Location": LOGIN_URL}),  # 3 RAAP
            FakeResponse(200, text=LOGIN_HTML),  # 4 /Login form
            FakeResponse(200, text=_a4j_redirect_xml(FRONTDOOR)),  # 5 POST /Login
            FakeResponse(200, text=FRONTDOOR_HTML),  # 6 frontdoor
            FakeResponse(200, text=LOGINFLOW_HTML),  # 7 LoginFlow
            FakeResponse(200, text=_a4j_redirect_xml(RAAP_B)),  # 8 POST /LoginFlow
            FakeResponse(200, text=raap_html),  # 9 RAAP authed -> tokens
        ]
    )
    cfg = SebAuthConfig(user="me@example.com", password="s3cret")
    auth = SebAuth(cfg, session=sess)
    tokens = auth.login()
    assert tokens.access_token == "AT"
    assert tokens.id_token == id_token
    assert tokens.refresh_token == "REFRESHNEW"
    assert tokens.expires_at == exp
    # the A4J login POST carried the credentials + view state
    login_post = sess.calls[4]
    assert login_post["method"] == "POST"
    assert login_post["url"] == "https://account.groupeseb.com/Login?sfdcIFrameOrigin=null"
    assert login_post["data"]["AJAXREQUEST"] == "_viewRoot"
    assert login_post["data"]["userEmail"] == "me@example.com"
    assert login_post["data"]["password"] == "s3cret"
    assert login_post["data"]["com.salesforce.visualforce.ViewState"] == "VS123"
    assert login_post["data"]["LoginPage:j_id4:j_id59"] == "LoginPage:j_id4:j_id59"
    # the LoginFlow auto-submit POST carried its own form fields
    flow_post = sess.calls[7]
    assert flow_post["url"] == "https://account.groupeseb.com/LoginFlow?sfdcIFrameOrigin=null"
    assert flow_post["data"]["LoginFlow:j_id5"] == "LoginFlow:j_id5"
    assert flow_post["data"]["LoginFlow:j_id5:j_id6"] == "LoginFlow:j_id5:j_id6"


def test_login_without_credentials_raises():
    auth = SebAuth(SebAuthConfig(), session=FakeSession())
    with pytest.raises(AuthenticationError, match="user and password"):
        auth.login()


def test_login_rejected_when_no_location_meta():
    sess = FakeSession(
        [
            FakeResponse(200, text=CONTINUATION_HTML),
            FakeResponse(302, headers={"Location": RAAP_A}),
            FakeResponse(302, headers={"Location": LOGIN_URL}),
            FakeResponse(200, text=LOGIN_HTML),
            FakeResponse(200, text="<partial-response>error</partial-response>"),
        ]
    )
    auth = SebAuth(SebAuthConfig(user="u", password="p"), session=sess)
    with pytest.raises(AuthenticationError, match="login rejected"):
        auth.login()


# -- helpers ------------------------------------------------------------------------------


def test_jwt_exp():
    exp = int(time.time()) + 120
    assert _jwt_exp(make_jwt(exp)) == exp
    assert _jwt_exp("not-a-jwt") is None


def test_parse_expiration_number_and_iso():
    assert _parse_expiration(1793102400.0) == 1793102400.0
    assert _parse_expiration("2026-10-27T12:00:00Z") == 1793102400.0
    assert _parse_expiration(None) is None
    assert _parse_expiration("garbage") is None


def test_iam_credentials_dataclass():
    c = IamCredentials(access_key_id="a", secret_key="b", session_token="c")
    assert c.expiration is None
