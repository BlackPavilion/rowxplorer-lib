"""SEB cloud authentication: OAuth tokens + Cognito IAM credentials.

The client authenticates against the SEB account platform
(``account.groupeseb.com``) with an OAuth *implicit flow* and then exchanges
the short-lived ``id_token`` for temporary AWS IAM credentials via Cognito
(``consumers.api.groupe-seb.com``). Those IAM credentials sign the MQTT
WebSocket connection (see :mod:`rowxplorer_lib.seb_mqtt`).

Token lifetimes (verified live, 2026-10-27):

- ``access_token`` / ``id_token``: ~120 s
- ``refresh_token``: long-lived, **not rotated** by the refresh endpoint
- Cognito IAM credentials: ~1 h

So the only secret a long-running client needs is the ``refresh_token``;
:meth:`SebAuth.refresh` mints fresh short-lived tokens on demand.
:meth:`SebAuth.login` re-runs the full OAuth flow (needs user/password) to
obtain a new ``refresh_token``.
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin

import requests

from .exceptions import (
    AuthenticationError,
)
from .exceptions import (
    ConnectionError as RowxplorerConnectionError,
)

# OAuth client id (the ``aud`` of the id_token).
DEFAULT_CLIENT_ID = (
    "3MVG99qusVZJwhskrTckKb5cJcZ6TRAFaBT4BFiKrzcUhle5GnfyASjYwMxTEEZruROQUz_lAj8HnLFbES7nv"
)
# API key of the ContinuationForExpId endpoint.
DEFAULT_APIKEY = "19UfOfJmK6365857UYNzjn427R6q1XFA"
DEFAULT_RCU_BASE = "https://account.groupeseb.com/"
DEFAULT_COGNITO_ENDPOINT = "consumers.api.groupe-seb.com"
DEFAULT_COGNITO_POOL_ID = "eu-west-1:f25c4598-48da-4fda-9c1a-27fe30bd2ffe"
# Cognito "provider name" for the SEB login token: host only (no scheme, no
# trailing slash). With "https://..." Cognito answers "Issuer doesn't match
# providerName".
DEFAULT_PROVIDER_KEY = "account.groupeseb.com"
DEFAULT_REGION = "eu-west-1"
DEFAULT_APP_VERSION = "10.0.0"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 16; Redmi K30 Pro Build/UKQ1.231108.001; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.186 "
    "Mobile Safari/537.36"
)


def _env(name: str, default: str = "") -> str:
    """Environment variable, cleaned for ``.env``-style values.

    Strips surrounding whitespace and any inline `` # ...`` comment (the
    workspace ``.env`` annotates values inline, e.g.
    ``IOT_COGNITO_ENDPOINT=consumers.api.groupe-seb.com   # hardcodeado``).
    """
    v = os.environ.get(name, default)
    v = v.split(" #", 1)[0]
    return v.strip()


@dataclass
class SebTokens:
    """OAuth tokens from the SEB account platform."""

    access_token: str
    id_token: str
    refresh_token: str | None = None
    scope: str | None = None
    token_type: str | None = None
    expires_at: float | None = None  # epoch seconds (id_token ``exp``)

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= time.time()


@dataclass
class IamCredentials:
    """Temporary AWS IAM credentials (from Cognito)."""

    access_key_id: str
    secret_key: str
    session_token: str
    expiration: float | None = None  # epoch seconds


@dataclass
class SebAuthConfig:
    """Configuration for :class:`SebAuth`.

    Attributes:
        refresh_token: long-lived OAuth refresh token (the only secret a
            running client needs).
        user / password: SEB account credentials, only for
            :meth:`SebAuth.login` (one-off, to obtain a refresh_token).
        client_id: OAuth client id (the ``aud`` of the id_token).
        apikey: ContinuationForExpId apikey (only for login).
        rcu_base: SEB account platform base URL.
        cognito_endpoint: Cognito proxy host (scheme optional).
        cognito_pool_id: Cognito identity pool.
        provider_key: Cognito login key (host only).
        region: AWS region of the IoT platform.
        app_version: app version sent in the OAuth flow.
        timeout: per-request timeout in seconds.
        user_agent: User-Agent for the OAuth flow (WebView-like).
    """

    refresh_token: str = ""
    user: str = ""
    password: str = ""
    client_id: str = DEFAULT_CLIENT_ID
    apikey: str = DEFAULT_APIKEY
    rcu_base: str = DEFAULT_RCU_BASE
    cognito_endpoint: str = DEFAULT_COGNITO_ENDPOINT
    cognito_pool_id: str = DEFAULT_COGNITO_POOL_ID
    provider_key: str = DEFAULT_PROVIDER_KEY
    region: str = DEFAULT_REGION
    app_version: str = DEFAULT_APP_VERSION
    timeout: float = 30.0
    user_agent: str = DEFAULT_USER_AGENT

    @classmethod
    def from_env(cls) -> SebAuthConfig:
        """Build the config from environment variables (``.env`` values)."""
        return cls(
            refresh_token=_env("IOT_REFRESH_TOKEN"),
            user=_env("SEB_USER"),
            password=_env("SEB_PASS"),
            client_id=_env("IOT_CLIENT_ID", DEFAULT_CLIENT_ID),
            cognito_endpoint=_env("IOT_COGNITO_ENDPOINT", DEFAULT_COGNITO_ENDPOINT),
            cognito_pool_id=_env("IOT_COGNITO_POOL_ID", DEFAULT_COGNITO_POOL_ID),
            region=_env("IOT_REGION", DEFAULT_REGION),
        )


class SebAuth:
    """Manages SEB OAuth tokens and Cognito IAM credentials.

    Typical usage (long-lived, only needs the refresh_token)::

        auth = SebAuth(SebAuthConfig(refresh_token="..."))
        creds = auth.cognito_credentials()   # refresh + Cognito, cached

    First-time setup (needs user/password, one-off)::

        auth = SebAuth(SebAuthConfig(user="me@example.com", password="..."))
        tokens = auth.login()
        print(tokens.refresh_token)          # store this
    """

    def __init__(self, config: SebAuthConfig, session: requests.Session | None = None):
        self.config = config
        self.session = session or requests.Session()
        self.session.headers.setdefault("User-Agent", config.user_agent)
        self.session.headers.setdefault(
            "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )
        self._tokens: SebTokens | None = None
        self._creds: IamCredentials | None = None

    # -- OAuth ---------------------------------------------------------------
    def refresh(self) -> SebTokens:
        """Exchange the long-lived ``refresh_token`` for fresh tokens.

        ``POST {rcu_base}services/oauth2/token?grant_type=refresh_token``.
        The refresh_token is **not rotated** by this endpoint.
        """
        if not self.config.refresh_token:
            raise AuthenticationError(
                "no refresh_token configured; run login() once to obtain one"
            )
        url = self.config.rcu_base.rstrip("/") + "/services/oauth2/token"
        try:
            resp = self.session.post(
                url,
                params={
                    "grant_type": "refresh_token",
                    "client_id": self.config.client_id,
                    "refresh_token": self.config.refresh_token,
                },
                headers={"Accept": "application/json"},
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            raise RowxplorerConnectionError(f"token refresh request failed: {exc}") from exc
        if resp.status_code != 200:
            raise AuthenticationError(
                f"token refresh failed (HTTP {resp.status_code}): {resp.text[:200]}"
            )
        try:
            data = resp.json()
        except ValueError:
            raise AuthenticationError(
                f"token refresh returned non-JSON: {resp.text[:200]}"
            ) from None
        tokens = self._parse_tokens(data)
        self._tokens = tokens
        return tokens

    def login(self) -> SebTokens:
        """Run the full OAuth implicit flow and return the tokens.

        Requires ``user`` and ``password`` in the config. The flow (one
        session, cookie jar; the ``source`` token is regenerated on every
        GET, so it cannot be split across sessions)::

            GET  /ContinuationForExpId?apikey=...        -> JS redirect
            GET  /services/oauth2/authorize/expid_...    -> 302 RAAP
            GET  /setup/secur/RemoteAccessAuthorizationPage -> 302 /Login
            GET  /Login?startURL=...                     -> Visualforce form
            POST /Login?sfdcIFrameOrigin=null (A4J)      -> frontdoor.jsp
            GET  frontdoor.jsp                           -> JS /apex/LoginFlow
            GET  /apex/LoginFlow                         -> A4J auto-submit
            POST /LoginFlow (A4J)                        -> RAAP (authed)
            GET  RAAP (authed)                           -> gsmoduser://tokens#...
        """
        if not (self.config.user and self.config.password):
            raise AuthenticationError("login() needs user and password in the config")
        s = self.session
        base = self.config.rcu_base

        # 1) ContinuationForExpId
        cont_url = base + "ContinuationForExpId?" + urlencode(
            {
                "apikey": self.config.apikey,
                "redirect_uri": "gsmoduser://tokens",
                "state": "STATE",
                "response_type": "token+id_token+refresh_token",
                "nonce": "NONCE",
                "isUserName": "false",
                "version": self.config.app_version,
            }
        )
        r = self._get(cont_url)
        auth_url = _js_redirect(r.text)
        if not auth_url:
            raise AuthenticationError("OAuth: no JS redirect in ContinuationForExpId")
        # 2) authorize -> 302 RAAP
        r = self._get(auth_url)
        raap_url = urljoin(auth_url, r.headers.get("Location", ""))
        # 3) RAAP -> 302 /Login
        r = self._get(raap_url)
        login_url = urljoin(raap_url, r.headers.get("Location", ""))
        # 4) GET /Login (Visualforce form)
        r = self._get(login_url)
        form = _parse_form(r.text)
        # 5) POST the A4J login (AJAXREQUEST + ViewState + credentials)
        post_url = urljoin(login_url, form["action"] or login_url)
        body: dict[str, str] = {"AJAXREQUEST": "_viewRoot"}
        body.update(form["inputs"])
        body["password"] = self.config.password
        body["userEmail"] = self.config.user
        sim = re.search(r"similarityGroupingId'\s*:\s*'([^']+)'", r.text)
        sim_id = sim.group(1) if sim else "LoginPage:j_id4:j_id59"
        body[sim_id] = sim_id
        r = s.post(
            post_url,
            data=body,
            allow_redirects=False,
            timeout=self.config.timeout,
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": login_url,
            },
        )
        mloc = re.search(r'<meta name="Location" content="([^"]+)"', r.text)
        if not mloc:
            raise AuthenticationError(
                f"OAuth: login rejected (HTTP {r.status_code}): {r.text[:200]}"
            )
        current = html.unescape(mloc.group(1))
        # 6+) follow the chain until gsmoduser://tokens
        tokens_url: str | None = None
        for _ in range(15):
            if current.startswith("gsmoduser://"):
                tokens_url = current
                break
            r = self._get(current)
            loc, _src = _next_url(r)
            if not loc:
                r2, _desc = _a4j_autosubmit(r.text, current, s, self.config.timeout)
                if r2 is not None:
                    loc, _src = _next_url(r2)
            if not loc:
                break
            current = urljoin(current, loc)
        if not tokens_url:
            raise AuthenticationError("OAuth: did not reach gsmoduser://tokens")
        frag = tokens_url.split("#", 1)[1] if "#" in tokens_url else ""
        params = dict(parse_qsl(frag))
        tokens = self._parse_tokens(params)
        self._tokens = tokens
        return tokens

    # -- id_token --------------------------------------------------------------
    def id_token(self) -> str:
        """Return a fresh ``id_token`` (refreshing it if it expires in <30 s)."""
        t = self._tokens
        if t is None or (t.expires_at or 0) - 30 < time.time():
            t = self.refresh()
        return t.id_token

    def access_token(self) -> str:
        """Return a fresh OAuth ``access_token`` (refreshing if needed)."""
        t = self._tokens
        if t is None or (t.expires_at or 0) - 30 < time.time():
            t = self.refresh()
        return t.access_token

    # -- Cognito -----------------------------------------------------------------
    def cognito_credentials(self) -> IamCredentials:
        """Temporary AWS IAM credentials via Cognito (cached until ~5 min
        before expiry).

        ``GetId -> GetOpenIdToken -> GetCredentialsForIdentity``, all against
        ``https://<cognito_endpoint>``.
        """
        now = time.time()
        c = self._creds
        if c is not None and (c.expiration or 0) - 300 > now:
            return c
        id_token = self.id_token()
        logins = {self.config.provider_key: id_token}
        identity_id = self._cognito(
            "GetId",
            {"IdentityPoolId": self.config.cognito_pool_id, "Logins": logins},
        )["IdentityId"]
        open_id = self._cognito(
            "GetOpenIdToken", {"IdentityId": identity_id, "Logins": logins}
        )["Token"]
        data = self._cognito(
            "GetCredentialsForIdentity",
            {
                "IdentityId": identity_id,
                "Logins": {"cognito-identity.amazonaws.com": open_id},
            },
        )
        c = data["Credentials"]
        creds = IamCredentials(
            access_key_id=c["AccessKeyId"],
            secret_key=c["SecretKey"],
            session_token=c["SessionToken"],
            expiration=_parse_expiration(c.get("Expiration")),
        )
        self._creds = creds
        return creds

    def _cognito(self, action: str, body: dict[str, Any]) -> dict[str, Any]:
        endpoint = self.config.cognito_endpoint
        if not endpoint.startswith(("http://", "https://")):
            endpoint = "https://" + endpoint
        try:
            resp = self.session.post(
                endpoint,
                json=body,
                headers={
                    "Content-Type": "application/x-amz-json-1.1",
                    "X-Amz-Target": f"AWSCognitoIdentityService.{action}",
                    "Accept": "application/json",
                },
                timeout=self.config.timeout,
            )
        except requests.RequestException as exc:
            raise RowxplorerConnectionError(f"Cognito {action} request failed: {exc}") from exc
        if resp.status_code != 200:
            raise AuthenticationError(
                f"Cognito {action} failed (HTTP {resp.status_code}): {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError:
            raise AuthenticationError(
                f"Cognito {action} returned non-JSON: {resp.text[:200]}"
            ) from None

    # -- helpers -------------------------------------------------------------------
    def _parse_tokens(self, data: dict[str, Any]) -> SebTokens:
        id_token = str(data.get("id_token") or "")
        return SebTokens(
            access_token=str(data.get("access_token") or ""),
            id_token=id_token,
            refresh_token=data.get("refresh_token") or self.config.refresh_token or None,
            scope=data.get("scope"),
            token_type=data.get("token_type"),
            expires_at=_jwt_exp(id_token),
        )

    def _get(self, url: str) -> requests.Response:
        try:
            return self.session.get(url, allow_redirects=False, timeout=self.config.timeout)
        except requests.RequestException as exc:
            raise RowxplorerConnectionError(f"OAuth request to {url} failed: {exc}") from exc


# -- OAuth page helpers (Visualforce / A4J) ----------------------------------------


def _jwt_exp(token: str) -> float | None:
    """``exp`` claim of a JWT (no signature check)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except (IndexError, KeyError, TypeError, ValueError):
        return None


def _parse_expiration(v: Any) -> float | None:
    """Cognito ``Expiration``: epoch number (SEB proxy) or ISO-8601 (AWS)."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _js_redirect(text: str) -> str | None:
    """URL of a JS redirect (``window.location.replace/href`` / handleRedirect)."""
    for pat in (
        r"window\.location\.replace\(\s*['\"](.*?)['\"]",
        r"window\.location\.href\s*=\s*['\"](.*?)['\"]",
        r"handleRedirect\(\s*['\"](.*?)['\"]",
    ):
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def _parse_form(text: str) -> dict[str, Any]:
    """Parse a Visualforce login form: action + all named inputs."""
    info: dict[str, Any] = {"action": None, "inputs": {}}
    fm = re.search(r"<form[^>]*>", text, re.IGNORECASE)
    if fm:
        am = re.search(r"action=[\"']([^\"']*)[\"']", fm.group(0), re.IGNORECASE)
        if am:
            info["action"] = am.group(1)
    for im in re.finditer(r"<input[^>]*>", text, re.IGNORECASE):
        itag = im.group(0)
        nm = re.search(r"name=[\"']([^\"']*)[\"']", itag)
        if not nm:
            continue
        vm = re.search(r"value=[\"']([^\"']*)[\"']", itag)
        info["inputs"][nm.group(1)] = html.unescape(vm.group(1)) if vm else ""
    return info


def _next_url(resp: requests.Response) -> tuple[str | None, str | None]:
    """Return the next URL from a response (header / JS / meta / A4J meta)."""
    loc = resp.headers.get("Location", "")
    if loc:
        return loc, "header"
    loc = _js_redirect(resp.text)
    if loc:
        return loc, "js"
    mm = re.search(r"<meta[^>]+http-equiv=[\"']refresh[\"'][^>]+url=([^\"'<>]+)", resp.text, re.IGNORECASE)
    if mm:
        return html.unescape(mm.group(1)), "meta"
    ma = re.search(r'<meta name="Location" content="([^"]+)"', resp.text)
    if ma:
        return html.unescape(ma.group(1)), "a4j-meta"
    return None, None


def _balanced(s: str, start: int) -> str | None:
    """Substring between balanced braces starting at ``s[start] == '{'``."""
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[start : i + 1]
    return None


def _a4j_autosubmit(
    page: str, base_url: str, session: requests.Session, timeout: float
) -> tuple[requests.Response | None, str | None]:
    """Detect an ``A4J.AJAX.Submit('FORM', null, OPTS)`` auto-executed on load
    (e.g. the ``LoginFlow`` page) and replay it as a POST.

    Returns ``(response, description)`` or ``(None, None)`` when the page has
    no such auto-submit.
    """
    if "A4J.AJAX.Submit" not in page:
        return None, None
    m = re.search(r"A4J\.AJAX\.Submit\(\s*['\"]([^'\"]+)['\"]\s*,\s*null\s*,", page)
    if not m:
        return None, None
    form_id = m.group(1)
    fm = re.search(
        r"<form[^>]*id=[\"']" + re.escape(form_id) + r"[\"'][^>]*>", page, re.IGNORECASE
    ) or re.search(r"<form[^>]*>", page, re.IGNORECASE)
    if not fm:
        return None, None
    tag = fm.group(0)
    am = re.search(r"action=[\"']([^\"']*)[\"']", tag, re.IGNORECASE)
    action = am.group(1) if am else base_url
    inputs: dict[str, str] = {}
    for im in re.finditer(r"<input[^>]*>", page, re.IGNORECASE):
        itag = im.group(0)
        nm = re.search(r"name=[\"']([^\"']*)[\"']", itag)
        if not nm:
            continue
        vm = re.search(r"value=[\"']([^\"']*)[\"']", itag)
        inputs[nm.group(1)] = html.unescape(vm.group(1)) if vm else ""
    params: dict[str, str] = {}
    pm = re.search(r"['\"]parameters['\"]\s*:\s*\{", page[m.end() :])
    if pm:
        inner = _balanced(page, m.end() + pm.end() - 1)
        if inner:
            for kv in re.finditer(r"['\"]([^'\"]+)['\"]\s*:\s*['\"]([^'\"]*)['\"]", inner):
                params[kv.group(1)] = html.unescape(kv.group(2))
    post_url = urljoin(base_url, action)
    body = {"AJAXREQUEST": "_viewRoot"}
    body.update(inputs)
    body.update(params)
    resp = session.post(
        post_url,
        data=body,
        allow_redirects=False,
        timeout=timeout,
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": base_url,
        },
    )
    return resp, f"A4J auto-submit form={form_id} params={list(params.keys())}"
