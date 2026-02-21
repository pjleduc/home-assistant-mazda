"""Config flow for Mazda Connected Services integration."""
from __future__ import annotations

import hashlib
import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, CONF_REGION
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, MAZDA_REGIONS
from .pymazda.client import Client as MazdaAPI
from .pymazda.exceptions import (
    MazdaAccountLockedException,
    MazdaAuthenticationException,
    MazdaException,
)

_LOGGER = logging.getLogger(__name__)


class MazdaConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Mazda Connected Services."""

    VERSION = 2

    def __init__(self) -> None:
        """Start the mazda config flow."""
        self._reauth_entry: config_entries.ConfigEntry | None = None
        self._region: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step — collect region, email, and password."""
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL].strip()
            password = user_input[CONF_PASSWORD]
            region = user_input[CONF_REGION]

            client = MazdaAPI.from_credentials(
                email=email,
                password=password,
                region=region,
            )
            try:
                await client.validate_credentials()
            except MazdaAuthenticationException:
                errors["base"] = "invalid_auth"
            except MazdaAccountLockedException:
                errors["base"] = "account_locked"
            except MazdaException as ex:
                _LOGGER.error("Error validating Mazda credentials: %s", ex)
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during Mazda login")
                errors["base"] = "unknown"
            finally:
                await client.close()

            if not errors:
                unique_id = hashlib.sha256(email.lower().encode()).hexdigest()[:16]
                await self.async_set_unique_id(unique_id)

                entry_data = {
                    CONF_EMAIL: email,
                    CONF_PASSWORD: password,
                    CONF_REGION: region,
                }

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
                    title=f"Mazda ({MAZDA_REGIONS.get(region, region)})",
                    data=entry_data,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(
                        CONF_REGION, default=self._region or "MNAO"
                    ): vol.In(MAZDA_REGIONS),
                }
            ),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> FlowResult:
        """Perform reauth if credentials have become invalid."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self._region = entry_data.get(CONF_REGION)
        return await self.async_step_user()
