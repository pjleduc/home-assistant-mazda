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

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_COUNTRY,
    CONF_EXPIRES_AT,
    CONF_REFRESH_TOKEN,
    COUNTRY_UI_LOCALES,
    DOMAIN,
    MAZDA_REGIONS,
    OAUTH2_REDIRECT_URI,
    OAUTH2_REGION_CONFIG,
    REGION_COUNTRIES,
    get_authorize_url,
    get_token_url,
    is_oauth2_supported,
)

_LOGGER = logging.getLogger(__name__)


def _generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and code_challenge (S256)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class MazdaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Mazda Connected Services."""

    VERSION = 2

    def __init__(self) -> None:
        """Start the mazda config flow."""
        self._reauth_entry: config_entries.ConfigEntry | None = None
        self._region: str | None = None
        self._country: str | None = None
        self._code_verifier: str | None = None
        self._state: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 1: Select region."""
        errors: dict[str, str] = {}

        if user_input is not None:
            region = user_input[CONF_REGION]

            if not is_oauth2_supported(region):
                errors["base"] = "region_not_supported"
            else:
                self._region = region
                return await self.async_step_country()

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

    async def async_step_country(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 2: Select country within the chosen region."""
        countries = REGION_COUNTRIES.get(self._region, {})

        # Skip country selection if only one country in the region
        if len(countries) == 1:
            self._country = next(iter(countries))
            return await self.async_step_auth()

        if user_input is not None:
            self._country = user_input[CONF_COUNTRY]
            return await self.async_step_auth()

        return self.async_show_form(
            step_id="country",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_COUNTRY, default=self._country
                    ): vol.In(countries),
                }
            ),
        )

    async def async_step_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 2: Show authorize URL and collect the redirect URL after login."""
        errors: dict[str, str] = {}

        if user_input is not None:
            redirect_url = user_input.get("redirect_url", "").strip()
            try:
                tokens = await self._handle_redirect_url(redirect_url)
            except ValueError as ex:
                _LOGGER.error("OAuth2 redirect handling failed: %s", ex)
                errors["base"] = str(ex)
            except aiohttp.ClientError as ex:
                _LOGGER.error("Token exchange network error: %s", ex)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during token exchange")
                errors["base"] = "unknown"

            if not errors:
                return await self._create_or_update_entry(tokens)

        # Generate PKCE pair and state for this attempt
        self._code_verifier, code_challenge = _generate_pkce_pair()
        self._state = secrets.token_urlsafe(32)

        authorize_url = self._build_authorize_url(code_challenge)

        return self.async_show_form(
            step_id="auth",
            description_placeholders={"authorize_url": authorize_url},
            data_schema=vol.Schema(
                {
                    vol.Required("redirect_url"): str,
                }
            ),
            errors=errors,
        )

    def _build_authorize_url(self, code_challenge: str) -> str:
        """Build the full OAuth2 authorize URL with PKCE."""
        oauth_config = OAUTH2_REGION_CONFIG[self._region]
        base_url = get_authorize_url(self._region)

        ui_locale = COUNTRY_UI_LOCALES.get(
            self._country, oauth_config.get("ui_locales", "en-US")
        )

        params = {
            "client_id": oauth_config["client_id"],
            "response_type": "code",
            "redirect_uri": OAUTH2_REDIRECT_URI,
            "scope": oauth_config["scope"],
            "response_mode": "query",
            "state": self._state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "ui_locales": ui_locale,
            "country": self._country,
        }

        return f"{base_url}?{urlencode(params)}"

    async def _handle_redirect_url(self, redirect_url: str) -> dict:
        """Parse the redirect URL and exchange the auth code for tokens."""
        if not redirect_url:
            raise ValueError("no_auth_code")

        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        # Check for error in redirect
        if "error" in params:
            error = params["error"][0]
            error_desc = params.get("error_description", [""])[0]
            _LOGGER.error("OAuth2 error: %s - %s", error, error_desc)
            raise ValueError("oauth_error")

        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]

        if not code:
            raise ValueError("no_auth_code")

        if state != self._state:
            _LOGGER.error(
                "State mismatch: expected %s, got %s", self._state, state
            )
            raise ValueError("invalid_state")

        return await self._exchange_code_for_tokens(code)

    async def _exchange_code_for_tokens(self, code: str) -> dict:
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

        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, data=token_data) as resp:
                resp_json = await resp.json()

                if resp.status != 200 or "access_token" not in resp_json:
                    error = resp_json.get("error", "unknown")
                    error_desc = resp_json.get("error_description", "")
                    _LOGGER.error(
                        "Token exchange failed (HTTP %s): %s - %s",
                        resp.status,
                        error,
                        error_desc,
                    )
                    raise ValueError("token_exchange_failed")

                return {
                    CONF_ACCESS_TOKEN: resp_json["access_token"],
                    CONF_REFRESH_TOKEN: resp_json.get("refresh_token"),
                    CONF_EXPIRES_AT: time.time() + resp_json.get(
                        "expires_in", 3600
                    ),
                }

    async def _create_or_update_entry(self, tokens: dict) -> FlowResult:
        """Create a new config entry or update an existing one."""
        entry_data = {
            CONF_REGION: self._region,
            CONF_COUNTRY: self._country,
            CONF_ACCESS_TOKEN: tokens[CONF_ACCESS_TOKEN],
            CONF_REFRESH_TOKEN: tokens[CONF_REFRESH_TOKEN],
            CONF_EXPIRES_AT: tokens[CONF_EXPIRES_AT],
        }

        # Use a hash of the access token as unique ID (we don't have email)
        # The token itself contains a sub claim we could decode, but this is simpler
        unique_id = hashlib.sha256(
            tokens[CONF_ACCESS_TOKEN].encode()
        ).hexdigest()[:16]
        await self.async_set_unique_id(unique_id)

        if self._reauth_entry:
            self.hass.config_entries.async_update_entry(
                self._reauth_entry, data=entry_data, unique_id=unique_id
            )
            self.hass.async_create_task(
                self.hass.config_entries.async_reload(
                    self._reauth_entry.entry_id
                )
            )
            return self.async_abort(reason="reauth_successful")

        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=f"Mazda ({MAZDA_REGIONS.get(self._region, self._region)})",
            data=entry_data,
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Perform reauth if tokens have become invalid."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self._region = entry_data.get(CONF_REGION)
        return await self.async_step_user()
