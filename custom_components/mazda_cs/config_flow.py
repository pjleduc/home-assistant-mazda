"""Config flow for Mazda Connected Services integration."""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_REGION
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import aiohttp_client

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_EXPIRES_AT,
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
                return await self.async_step_authorize()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_REGION, default=self._region
                    ): vol.In(MAZDA_REGIONS),
                }
            ),
            errors=errors,
        )

    async def async_step_authorize(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the OAuth2 authorization step.

        Shows the user a login URL to visit, then asks them to paste
        the redirect URL containing the authorization code.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            redirect_url = user_input.get(CONF_REDIRECT_URL, "").strip()
            if not redirect_url:
                errors["base"] = "missing_redirect_url"
            else:
                # Extract auth code from redirect URL
                code = self._extract_code_from_url(redirect_url)
                if code is None:
                    errors["base"] = "invalid_redirect_url"
                else:
                    # Exchange code for tokens
                    try:
                        token_data = await self._exchange_code_for_tokens(code)
                    except Exception:
                        _LOGGER.exception("Token exchange failed")
                        errors["base"] = "token_exchange_failed"
                    else:
                        return await self._async_finish_setup(token_data)

        # Generate PKCE pair and state for this attempt
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

        return self.async_show_form(
            step_id="authorize",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_REDIRECT_URL): str,
                }
            ),
            description_placeholders={"authorize_url": authorize_url},
            errors=errors,
        )

    def _extract_code_from_url(self, url: str) -> str | None:
        """Extract the authorization code from a redirect URL."""
        try:
            parsed = urlparse(url)
            # The redirect URL uses a custom scheme: msauth://...?code=XXX&state=YYY
            # Parse query params from the query string or fragment
            query_params = parse_qs(parsed.query)
            if not query_params:
                # Some browsers put params in the fragment
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
            raise Exception(f"Token exchange failed: {error}")

        return resp_json

    async def _async_finish_setup(
        self, token_data: dict[str, Any]
    ) -> FlowResult:
        """Create or update the config entry with OAuth tokens."""
        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token", "")
        expires_in = token_data.get("expires_in", 3600)
        expires_at = time.time() + expires_in

        # Try to extract a unique ID from the id_token JWT (sub claim)
        unique_id = self._extract_sub_from_id_token(
            token_data.get("id_token", "")
        )
        if unique_id is None:
            # Fallback: use a hash of the access token
            unique_id = hashlib.sha256(access_token.encode()).hexdigest()[:16]

        await self.async_set_unique_id(unique_id)

        entry_data = {
            CONF_REGION: self._region,
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
            # JWT has 3 parts separated by dots; payload is the second part
            parts = id_token.split(".")
            if len(parts) < 2:
                return None
            # Add padding
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
        return await self.async_step_user()
