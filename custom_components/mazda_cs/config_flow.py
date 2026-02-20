"""Config flow for Mazda Connected Services integration."""
from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlparse

import aiohttp

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_REGION
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import aiohttp_client

from .const import (
    AUTH_METHOD_OAUTH2,
    CONF_ACCESS_TOKEN,
    CONF_AUTH_METHOD,
    CONF_EMAIL,
    CONF_EXPIRES_AT,
    CONF_PASSWORD,
    CONF_REFRESH_TOKEN,
    DOMAIN,
    MAZDA_REGIONS,
    OAUTH2_REDIRECT_URI,
    OAUTH2_REGION_CONFIG,
    get_authorize_url,
    get_token_url,
    is_oauth2_supported,
)

_LOGGER = logging.getLogger(__name__)

CONF_REDIRECT_URL = "redirect_url"


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code verifier and challenge pair."""
    code_verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    )
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    )
    return code_verifier, code_challenge


class MazdaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Mazda Connected Services."""

    VERSION = 2

    def __init__(self) -> None:
        """Start the mazda config flow."""
        self._reauth_entry: config_entries.ConfigEntry | None = None
        self._region: str | None = None
        self._code_verifier: str | None = None
        self._state: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle region selection step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            region = user_input[CONF_REGION]
            if not is_oauth2_supported(region):
                errors["base"] = "oauth2_not_supported"
            else:
                self._region = region
                return await self.async_step_credentials()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_REGION, default=self._region or "MNAO"
                    ): vol.In(MAZDA_REGIONS),
                }
            ),
            errors=errors,
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle email/password login — performs OAuth2 headlessly."""
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            password = user_input[CONF_PASSWORD]

            try:
                token_data = await self._headless_oauth2_login(email, password)
            except MazdaHeadlessAuthError as ex:
                _LOGGER.error("Headless OAuth2 login failed: %s", ex)
                if "invalid" in str(ex).lower() or "password" in str(ex).lower():
                    errors["base"] = "invalid_auth"
                elif "locked" in str(ex).lower():
                    errors["base"] = "account_locked"
                else:
                    errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during headless OAuth2 login")
                errors["base"] = "cannot_connect"
            else:
                return await self._async_finish_setup(token_data, email, password)

        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def _headless_oauth2_login(
        self, email: str, password: str
    ) -> dict[str, Any]:
        """Perform OAuth2 login programmatically via Azure AD B2C.

        Simulates what the MyMazda app does internally:
        1. Load the authorize page to get CSRF token and transaction ID
        2. POST credentials to the SelfAsserted endpoint
        3. Follow the confirmed endpoint to get the auth code
        4. Exchange the auth code for tokens
        """
        self._code_verifier, code_challenge = _generate_pkce_pair()
        self._state = secrets.token_urlsafe(32)

        authorize_base = get_authorize_url(self._region)
        oauth_config = OAUTH2_REGION_CONFIG[self._region]

        params = {
            "response_type": "code",
            "client_id": oauth_config["client_id"],
            "redirect_uri": OAUTH2_REDIRECT_URI,
            "scope": oauth_config["scope"],
            "state": self._state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        authorize_url = f"{authorize_base}?{urlencode(params)}"

        base_url = oauth_config["auth_base_url"]

        # Use an isolated session with its own cookie jar to avoid
        # interference from HA's shared session cookies
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        browser_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Mobile Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }

        async with aiohttp.ClientSession(
            cookie_jar=cookie_jar, headers=browser_headers
        ) as session:
            # Step 1: Load the authorize page to extract CSRF and transId
            _LOGGER.warning("Headless OAuth2: loading authorize page: %s", authorize_url)
            try:
                resp = await session.get(
                    authorize_url,
                    allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
                )
            except Exception as ex:
                _LOGGER.error("Headless OAuth2: failed to load authorize page: %s", ex)
                raise MazdaHeadlessAuthError(f"Failed to load authorize page: {ex}") from ex
            page_html = await resp.text()
            page_url = str(resp.url)
            _LOGGER.warning("Headless OAuth2: authorize page status=%s url=%s length=%d", resp.status, page_url, len(page_html))

            csrf_token = self._extract_setting(page_html, "csrf")
            trans_id = self._extract_setting(page_html, "transId")

            _LOGGER.warning("Headless OAuth2: csrf=%s transId=%s", csrf_token is not None, trans_id is not None)

            # Dump key SETTINGS values from the page for debugging
            api_url_match = re.search(r'"api"\s*:\s*"([^"]+)"', page_html)
            hosts_match = re.search(r'"hosts"\s*:\s*\{[^}]+\}', page_html)
            _LOGGER.warning(
                "Headless OAuth2: page api=%s hosts=%s",
                api_url_match.group(1) if api_url_match else "NOT_FOUND",
                hosts_match.group(0)[:300] if hosts_match else "NOT_FOUND",
            )

            if not csrf_token or not trans_id:
                _LOGGER.error(
                    "Could not extract CSRF/transId from login page (url=%s, length=%d, first500=%s)",
                    page_url,
                    len(page_html),
                    page_html[:500],
                )
                raise MazdaHeadlessAuthError(
                    "Could not extract CSRF token or transaction ID from login page"
                )

            # Extract the tenant path from the page SETTINGS to get the
            # correct casing (e.g. B2C_1A_signin vs B2C_1A_SIGNIN)
            tenant_path = None
            tenant_match = re.search(
                r'"hosts"\s*:\s*\{\s*"tenant"\s*:\s*"([^"]+)"', page_html
            )
            if tenant_match:
                tenant_path = tenant_match.group(1)
            if not tenant_path:
                tenant_path = f"/{oauth_config['tenant_id']}/{oauth_config['policy']}"

            # Extract the actual policy name from the tenant_path so the p=
            # parameter matches the casing used by Azure AD B2C
            actual_policy = oauth_config["policy"]
            tenant_parts = tenant_path.strip("/").split("/")
            if len(tenant_parts) >= 2:
                actual_policy = tenant_parts[-1]

            _LOGGER.warning("Headless OAuth2: tenant_path=%s actual_policy=%s", tenant_path, actual_policy)

            # Step 2: POST credentials to SelfAsserted
            self_asserted_url = (
                f"{base_url}{tenant_path}/SelfAsserted"
                f"?tx={quote(trans_id, safe='')}"
                f"&p={quote(actual_policy, safe='')}"
            )
            _LOGGER.warning("Headless OAuth2: SelfAsserted URL=%s", self_asserted_url)

            form_data = {
                "request_type": "RESPONSE",
                "signInName": email,
                "password": password,
            }

            headers = {
                "X-CSRF-TOKEN": csrf_token,
                "X-Requested-With": "XMLHttpRequest",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Referer": page_url,
                "Origin": base_url,
            }

            resp2 = await session.post(
                self_asserted_url,
                data=form_data,
                headers=headers,
                allow_redirects=False,
            )

            resp2_text = await resp2.text()
            _LOGGER.warning(
                "Headless OAuth2: SelfAsserted response status=%s headers=%s body=%s",
                resp2.status,
                dict(resp2.headers),
                resp2_text[:500],
            )
            _LOGGER.warning(
                "Headless OAuth2: session cookies=%s",
                {k: v.value for k, v in session.cookie_jar.filter_cookies(self_asserted_url).items()},
            )

            # Check for error in response
            if resp2.status != 200:
                raise MazdaHeadlessAuthError(
                    f"SelfAsserted returned status {resp2.status}: {resp2_text[:200]}"
                )

            # Azure AD B2C returns JSON with status for AJAX calls
            if '"status":"400"' in resp2_text or '"status":"409"' in resp2_text:
                # Extract error message if available
                error_msg = "Invalid email or password"
                msg_match = re.search(r'"message"\s*:\s*"([^"]+)"', resp2_text)
                if msg_match:
                    error_msg = msg_match.group(1)
                raise MazdaHeadlessAuthError(error_msg)

            # Step 3: GET the confirmed endpoint to get the auth code redirect
            _LOGGER.warning("Headless OAuth2: requesting confirmed endpoint")
            confirmed_url = (
                f"{base_url}{tenant_path}/api/CombinedSigninAndSignup/confirmed"
                f"?rememberMe=true"
                f"&csrf_token={quote(csrf_token, safe='')}"
                f"&tx={quote(trans_id, safe='')}"
                f"&p={quote(actual_policy, safe='')}"
            )

            resp3 = await session.get(
                confirmed_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": page_url,
                },
                allow_redirects=False,
            )

            _LOGGER.warning(
                "Headless OAuth2: confirmed response status=%s", resp3.status
            )

            # The response should be a 302 redirect to the redirect_uri with the code
            if resp3.status not in (302, 303):
                resp3_text = await resp3.text()
                _LOGGER.error(
                    "Headless OAuth2: confirmed endpoint did not redirect. "
                    "status=%s, body=%s",
                    resp3.status,
                    resp3_text[:500],
                )
                raise MazdaHeadlessAuthError(
                    f"Expected redirect from confirmed endpoint, got status {resp3.status}: {resp3_text[:200]}"
                )

            redirect_location = resp3.headers.get("Location", "")
            _LOGGER.warning(
                "Headless OAuth2: redirect location=%s", redirect_location[:200]
            )

            code = self._extract_code_from_url(redirect_location)
            if code is None:
                raise MazdaHeadlessAuthError(
                    f"Could not extract auth code from redirect: {redirect_location[:200]}"
                )

        # Step 4: Exchange code for tokens (outside isolated session)
        _LOGGER.warning("Headless OAuth2: exchanging code for tokens")
        return await self._exchange_code_for_tokens(code)

    @staticmethod
    def _extract_setting(html: str, key: str) -> str | None:
        """Extract a value from the SETTINGS JavaScript object in the page."""
        # Match patterns like "csrf":"value" or "transId":"value"
        pattern = rf'"{key}"\s*:\s*"([^"]+)"'
        match = re.search(pattern, html)
        if match:
            return match.group(1)
        return None

    def _extract_code_from_url(self, url: str) -> str | None:
        """Extract the authorization code from a redirect URL."""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if not query_params:
                query_params = parse_qs(parsed.fragment)

            code_list = query_params.get("code")
            if code_list:
                return code_list[0]
        except Exception:
            _LOGGER.debug("Failed to parse redirect URL: %s", url)
        return None

    async def _exchange_code_for_tokens(
        self, code: str
    ) -> dict[str, Any]:
        """Exchange an authorization code for access and refresh tokens."""
        token_url = get_token_url(self._region)
        oauth_config = OAUTH2_REGION_CONFIG[self._region]

        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OAUTH2_REDIRECT_URI,
            "client_id": oauth_config["client_id"],
            "code_verifier": self._code_verifier,
            "scope": oauth_config["scope"],
        }

        websession = aiohttp_client.async_get_clientsession(self.hass)
        resp = await websession.post(token_url, data=token_data)
        resp_json = await resp.json()

        if resp.status != 200 or "access_token" not in resp_json:
            error = resp_json.get("error", "unknown")
            error_desc = resp_json.get("error_description", "")
            _LOGGER.error("Token exchange failed: %s - %s", error, error_desc)
            raise MazdaHeadlessAuthError(f"Token exchange failed: {error}")

        return resp_json

    async def _async_finish_setup(
        self, token_data: dict[str, Any], email: str, password: str
    ) -> FlowResult:
        """Create or update the config entry with OAuth tokens and credentials."""
        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token", "")
        expires_in = token_data.get("expires_in", 3600)
        expires_at = time.time() + expires_in

        # Try to extract a unique ID from the id_token JWT (sub claim)
        unique_id = self._extract_sub_from_id_token(
            token_data.get("id_token", "")
        )
        if unique_id is None:
            unique_id = hashlib.sha256(email.lower().encode()).hexdigest()[:16]

        await self.async_set_unique_id(unique_id)

        entry_data = {
            CONF_REGION: self._region,
            CONF_AUTH_METHOD: AUTH_METHOD_OAUTH2,
            CONF_EMAIL: email,
            CONF_PASSWORD: password,
            CONF_ACCESS_TOKEN: access_token,
            CONF_REFRESH_TOKEN: refresh_token,
            CONF_EXPIRES_AT: expires_at,
        }

        if self._reauth_entry:
            self.hass.config_entries.async_update_entry(
                self._reauth_entry, data=entry_data, unique_id=unique_id
            )
            self.hass.async_create_task(
                self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
            )
            return self.async_abort(reason="reauth_successful")

        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=f"Mazda ({MAZDA_REGIONS.get(self._region, self._region)})",
            data=entry_data,
        )

    def _extract_sub_from_id_token(self, id_token: str) -> str | None:
        """Extract the 'sub' claim from a JWT id_token without verification."""
        if not id_token:
            return None
        try:
            parts = id_token.split(".")
            if len(parts) < 2:
                return None
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            import json

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return payload.get("sub")
        except Exception:
            return None

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Perform reauth if tokens have expired."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self._region = entry_data.get(CONF_REGION)
        return await self.async_step_credentials()


class MazdaHeadlessAuthError(Exception):
    """Error during headless OAuth2 authentication."""
