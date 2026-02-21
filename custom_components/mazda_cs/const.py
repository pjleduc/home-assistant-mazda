"""Constants for the Mazda Connected Services integration."""

DOMAIN = "mazda_cs"

DATA_CLIENT = "mazda_client"
DATA_COORDINATOR = "coordinator"
DATA_REGION = "region"
DATA_VEHICLES = "vehicles"

MAZDA_REGIONS = {"MNAO": "North America", "MME": "Europe", "MJO": "Japan"}

# Country choices per region (B2C requires matching the account's registered country)
REGION_COUNTRIES = {
    "MNAO": {"US": "United States", "CA": "Canada"},
    "MME": {
        "GB": "United Kingdom",
        "DE": "Germany",
        "AT": "Austria",
        "CH": "Switzerland",
        "FR": "France",
        "ES": "Spain",
        "IT": "Italy",
        "NL": "Netherlands",
        "BE": "Belgium",
        "PT": "Portugal",
        "PL": "Poland",
        "CZ": "Czech Republic",
        "SE": "Sweden",
        "NO": "Norway",
        "DK": "Denmark",
        "FI": "Finland",
        "IE": "Ireland",
    },
    "MJO": {"JP": "Japan"},
}

# Map country code to ui_locales value for the B2C login page
COUNTRY_UI_LOCALES = {
    "US": "en-US",
    "CA": "en-CA",
    "GB": "en-GB",
    "DE": "de-DE",
    "AT": "de-AT",
    "CH": "de-CH",
    "FR": "fr-FR",
    "ES": "es-ES",
    "IT": "it-IT",
    "NL": "nl-NL",
    "BE": "nl-BE",
    "PT": "pt-PT",
    "PL": "pl-PL",
    "CZ": "cs-CZ",
    "SE": "sv-SE",
    "NO": "nb-NO",
    "DK": "da-DK",
    "FI": "fi-FI",
    "IE": "en-IE",
    "JP": "ja",
}

CONF_COUNTRY = "country"

# OAuth2 token storage keys
CONF_ACCESS_TOKEN = "access_token"
CONF_REFRESH_TOKEN = "refresh_token"
CONF_EXPIRES_AT = "expires_at"

# Per-region OAuth2 configuration (Azure AD B2C)
OAUTH2_REGION_CONFIG = {
    "MNAO": {
        "auth_base_url": "https://na.id.mazda.com",
        "tenant_id": "47801034-62d1-49f6-831b-ffdcf04f13fc",
        "policy": "B2C_1A_SIGNIN",
        "client_id": "2daf581c-65c1-4fdb-b46a-efa98c6ba5b7",
        "scope": "openid offline_access profile https://pduspb2c01.onmicrosoft.com/0728deea-be48-4382-9ef1-d4ff6d679ffa/cv",
        "ui_locales": "en-US",
    },
    "MME": {
        "auth_base_url": "https://eu.id.mazda.com",
        "tenant_id": "432b587f-88ad-40aa-9e5d-e6bcf9429e8d",
        "policy": "B2C_1A_signin",
        "client_id": "cbfe43e1-6949-42fe-996e-1a56f41a891d",
        "scope": "https://pdeupb2c01.onmicrosoft.com/dcd35c5a-b32f-4add-ac6c-ba6e8bbfa11b/cv openid profile offline_access",
        "ui_locales": "en-GB",
    },
    "MJO": {
        "auth_base_url": "https://ap.id.mazda.com",
        "tenant_id": None,
        "policy": "B2C_1A_SIGNIN",
        "client_id": None,
        "scope": None,
        "ui_locales": "ja",
    },
}

# Redirect URI matching the Mazda Android app registration
OAUTH2_REDIRECT_URI = "msauth://com.interrait.mymazda/%2FnKMu1%2BlCjy5%2Be7OF9vfp4eFBks%3D"


def get_authorize_url(region):
    """Build the OAuth2 authorize URL for a given region."""
    config = OAUTH2_REGION_CONFIG.get(region)
    if config is None or config.get("tenant_id") is None:
        return None
    return (
        f"{config['auth_base_url']}/{config['tenant_id']}"
        f"/{config['policy']}/oauth2/v2.0/authorize"
    )


def get_token_url(region):
    """Build the OAuth2 token URL for a given region."""
    config = OAUTH2_REGION_CONFIG.get(region)
    if config is None or config.get("tenant_id") is None:
        return None
    return (
        f"{config['auth_base_url']}/{config['tenant_id']}"
        f"/{config['policy']}/oauth2/v2.0/token"
    )


def is_oauth2_supported(region):
    """Check if OAuth2 is configured for a given region."""
    config = OAUTH2_REGION_CONFIG.get(region)
    return config is not None and config.get("tenant_id") is not None
