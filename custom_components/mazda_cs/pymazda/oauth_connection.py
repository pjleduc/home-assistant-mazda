"""OAuth2-based connection to the Mazda API."""

import asyncio
import base64
import hashlib
import json
import logging
import time
from urllib.parse import urlencode

from .crypto_utils import (
    decrypt_aes128cbc_buffer_to_str,
    encrypt_aes128cbc_buffer_to_base64_str,
)
from .exceptions import (
    MazdaAPIEncryptionException,
    MazdaAuthenticationException,
    MazdaConfigException,
    MazdaException,
    MazdaLoginFailedException,
    MazdaRequestInProgressException,
    MazdaTokenExpiredException,
)
from .sensordata.sensor_data_builder import SensorDataBuilder

IV = "0102030405060708"
SIGNATURE_MD5 = "C383D8C4D279B78130AD52DC71D95CAA"
APP_PACKAGE_ID = "com.interrait.mymazda"
USER_AGENT_BASE_API = "MyMazda-Android/9.0.8"
APP_OS = "Android"
APP_VERSION = "9.0.8"

# Region config for the new API.
# Two hosts per region:
#   remote_services_url: for remoteServices/* and service/checkVersion (new host)
#   base_url: for junction/*, content/*, miox/* endpoints (original /prod/ host)
REGION_CONFIG = {
    "MNAO": {
        "app_code": "498345786246797888995",
        "app_code_old": "202007270941270111799",
        "remote_services_url": "https://hgs2ivna.mazda.com/",
        "base_url": "https://0cxo7m58.mazda.com/prod/",
        "region_code": "us",
    },
    "MME": {
        "app_code": "202008100250281064816",
        "app_code_old": "202008100250281064816",
        "remote_services_url": "https://hgs2iveu.mazda.com/",
        "base_url": "https://e9stj7g7.mazda.com/prod/",
        "region_code": "eu",
    },
    "MJO": {
        "app_code": "202009170613074283422",
        "app_code_old": "202009170613074283422",
        "remote_services_url": "https://hgs2ivap.mazda.com/",
        "base_url": "https://wcs9p6wj.mazda.com/prod/",
        "region_code": "jp",
    },
}

MAX_RETRIES = 4


class OAuthConnection:
    """Mazda API connection using OAuth2 Bearer tokens."""

    def __init__(
        self,
        region,
        websession,
        access_token,
        refresh_token,
        expires_at,
        token_update_callback=None,
    ):
        """Initialize the OAuth connection."""
        if region not in REGION_CONFIG:
            raise MazdaConfigException("Invalid region")

        region_config = REGION_CONFIG[region]
        self.region = region
        self.app_code = region_config["app_code"]
        self.app_code_old = region_config["app_code_old"]
        self.remote_services_url = region_config["remote_services_url"]
        self.base_url = region_config["base_url"]
        self.region_code = region_config["region_code"]

        self._session = websession
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self._token_update_callback = token_update_callback

        self.enc_key = None
        self.sign_key = None

        self.base_api_device_id = "D5FC5CA0-FD3B-40DB-9ADF-3F4F22B7D491"

        self.sensor_data_builder = SensorDataBuilder()
        self.logger = logging.getLogger(__name__)

    def __get_timestamp_str_ms(self):
        return str(int(round(time.time() * 1000)))

    def __get_decryption_key_from_app_code(self, app_code):
        val1 = (
            hashlib.md5((app_code + APP_PACKAGE_ID).encode()).hexdigest().upper()
        )
        val2 = hashlib.md5((val1 + SIGNATURE_MD5).encode()).hexdigest().lower()
        return val2[4:20]

    def __get_temporary_sign_key_from_app_code(self, app_code):
        val1 = (
            hashlib.md5((app_code + APP_PACKAGE_ID).encode()).hexdigest().upper()
        )
        val2 = hashlib.md5((val1 + SIGNATURE_MD5).encode()).hexdigest().lower()
        return val2[20:32] + val2[0:10] + val2[4:6]

    def __get_sign_from_timestamp(self, timestamp, app_code):
        if timestamp is None or timestamp == "":
            return ""
        timestamp_extended = (timestamp + timestamp[6:] + timestamp[3:]).upper()
        temporary_sign_key = self.__get_temporary_sign_key_from_app_code(app_code)
        return self.__get_payload_sign(timestamp_extended, temporary_sign_key).upper()

    def __get_sign_from_payload_and_timestamp(self, payload, timestamp):
        if timestamp is None or timestamp == "":
            return ""
        if self.sign_key is None or self.sign_key == "":
            raise MazdaException("Missing sign key")

        return self.__get_payload_sign(
            self.__encrypt_payload_using_key(payload)
            + timestamp
            + timestamp[6:]
            + timestamp[3:],
            self.sign_key,
        )

    def __get_payload_sign(self, encrypted_payload_and_timestamp, sign_key):
        return (
            hashlib.sha256((encrypted_payload_and_timestamp + sign_key).encode())
            .hexdigest()
            .upper()
        )

    def __encrypt_payload_using_key(self, payload):
        if self.enc_key is None or self.enc_key == "":
            raise MazdaException("Missing encryption key")
        if payload is None or payload == "":
            return ""

        return encrypt_aes128cbc_buffer_to_base64_str(
            payload.encode("utf-8"), self.enc_key, IV
        )

    def __decrypt_payload_using_app_code(self, payload, app_code):
        buf = base64.b64decode(payload)
        key = self.__get_decryption_key_from_app_code(app_code)
        decrypted = decrypt_aes128cbc_buffer_to_str(buf, key, IV)
        return json.loads(decrypted)

    def __decrypt_payload_using_key(self, payload):
        if self.enc_key is None or self.enc_key == "":
            raise MazdaException("Missing encryption key")

        buf = base64.b64decode(payload)
        decrypted = decrypt_aes128cbc_buffer_to_str(buf, self.enc_key, IV)
        return json.loads(decrypted)

    def _get_url_and_app_code_for_uri(self, uri):
        """Determine which host and app_code to use based on the URI.

        remoteServices/* and service/checkVersion go to the remote services host.
        junction/*, content/*, miox/*, howTo/* go to the base /prod/ host.
        """
        if uri.startswith("remoteServices/") or uri == "service/checkVersion":
            return self.remote_services_url, self.app_code
        return self.base_url, self.app_code_old

    async def ensure_token_valid(self):
        """Check token expiry and refresh if needed."""
        if self.access_token is None or self.refresh_token is None:
            raise MazdaAuthenticationException("No OAuth tokens available")

        if self.expires_at is not None and self.expires_at > time.time() + 60:
            return  # Token still valid with 60s buffer

        self.logger.info("OAuth2 access token expired or expiring soon, refreshing")
        await self._refresh_access_token()

    async def _refresh_access_token(self):
        """Refresh the access token using the refresh token."""
        from ..const import (
            OAUTH2_REDIRECT_URI,
            OAUTH2_REGION_CONFIG,
            get_token_url,
        )

        token_url = get_token_url(self.region)
        if token_url is None:
            raise MazdaException(f"OAuth2 not configured for region {self.region}")

        oauth_config = OAUTH2_REGION_CONFIG[self.region]

        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": oauth_config["client_id"],
            "scope": oauth_config["scope"],
            "redirect_uri": OAUTH2_REDIRECT_URI,
        }

        resp = await self._session.post(token_url, data=token_data)
        resp_json = await resp.json()

        if resp.status != 200 or "access_token" not in resp_json:
            error = resp_json.get("error", "unknown")
            error_desc = resp_json.get("error_description", "")
            self.logger.error("Token refresh failed: %s - %s", error, error_desc)
            raise MazdaAuthenticationException(f"Token refresh failed: {error}")

        self.access_token = resp_json["access_token"]
        if "refresh_token" in resp_json:
            self.refresh_token = resp_json["refresh_token"]
        self.expires_at = time.time() + resp_json.get("expires_in", 3600)

        self.logger.info("OAuth2 token refreshed successfully")

        if self._token_update_callback:
            self._token_update_callback(
                self.access_token, self.refresh_token, self.expires_at
            )

    async def api_request(
        self,
        method,
        uri,
        query_dict=None,
        body_dict=None,
        needs_keys=True,
        needs_auth=False,
    ):
        """Send an API request."""
        return await self.__api_request_retry(
            method,
            uri,
            query_dict or {},
            body_dict or {},
            needs_keys,
            needs_auth,
            num_retries=0,
        )

    async def __api_request_retry(
        self,
        method,
        uri,
        query_dict,
        body_dict,
        needs_keys,
        needs_auth,
        num_retries,
    ):
        if num_retries > MAX_RETRIES:
            raise MazdaException("Request exceeded max number of retries")

        if needs_keys:
            await self.__ensure_keys_present()
        if needs_auth:
            await self.__ensure_token_is_valid()

        retry_message = (
            (" - attempt #" + str(num_retries + 1)) if (num_retries > 0) else ""
        )
        self.logger.debug("Sending %s request to %s%s", method, uri, retry_message)

        try:
            return await self.__send_api_request(
                method, uri, query_dict, body_dict, needs_keys, needs_auth
            )
        except MazdaAPIEncryptionException:
            self.logger.info(
                "Server reports request was not encrypted properly. "
                "Retrieving new encryption keys."
            )
            await self.__retrieve_keys()
            return await self.__api_request_retry(
                method, uri, query_dict, body_dict,
                needs_keys, needs_auth, num_retries + 1,
            )
        except MazdaTokenExpiredException:
            self.logger.info(
                "Server reports access token was expired. Refreshing."
            )
            await self._refresh_access_token()
            return await self.__api_request_retry(
                method, uri, query_dict, body_dict,
                needs_keys, needs_auth, num_retries + 1,
            )
        except MazdaLoginFailedException:
            self.logger.warning("Request failed for an unknown reason. Trying again.")
            await self._refresh_access_token()
            return await self.__api_request_retry(
                method, uri, query_dict, body_dict,
                needs_keys, needs_auth, num_retries + 1,
            )
        except MazdaRequestInProgressException:
            self.logger.info(
                "Request failed because another request was already in progress. "
                "Waiting 30 seconds and trying again."
            )
            await asyncio.sleep(30)
            return await self.__api_request_retry(
                method, uri, query_dict, body_dict,
                needs_keys, needs_auth, num_retries + 1,
            )

    async def __send_api_request(
        self,
        method,
        uri,
        query_dict,
        body_dict,
        needs_keys,
        needs_auth,
    ):
        timestamp = self.__get_timestamp_str_ms()
        url, app_code = self._get_url_and_app_code_for_uri(uri)

        original_query_str = ""
        encrypted_query_dict = {}

        if query_dict:
            original_query_str = urlencode(query_dict)
            encrypted_query_dict["params"] = self.__encrypt_payload_using_key(
                original_query_str
            )

        original_body_str = ""
        encrypted_body_str = ""
        if body_dict:
            original_body_str = json.dumps(body_dict)
            encrypted_body_str = self.__encrypt_payload_using_key(original_body_str)

        headers = {
            "device-id": self.base_api_device_id,
            "app-code": app_code,
            "app-os": APP_OS,
            "user-agent": USER_AGENT_BASE_API,
            "app-version": APP_VERSION,
            "app-unique-id": APP_PACKAGE_ID,
            "access-token": (self.access_token if needs_auth else ""),
            "X-acf-sensor-data": self.sensor_data_builder.generate_sensor_data(),
            "language": "en",
            "locale": "en-US",
            "region": self.region_code,
            "req-id": "req_" + timestamp,
            "timestamp": timestamp,
            "Accept": "*/*, application/json",
            "Accept-Charset": "UTF-8",
        }

        if needs_auth:
            headers["Authorization"] = f"Bearer {self.access_token}"

        if "checkVersion" in uri:
            headers["sign"] = self.__get_sign_from_timestamp(timestamp, app_code)
        elif method == "GET":
            headers["sign"] = self.__get_sign_from_payload_and_timestamp(
                original_query_str, timestamp
            )
        elif method == "POST":
            headers["sign"] = self.__get_sign_from_payload_and_timestamp(
                original_body_str, timestamp
            )

        if method == "POST" and encrypted_body_str:
            headers["Content-Type"] = "text/plain; charset=UTF-8"

        response = await self._session.request(
            method,
            url + uri,
            headers=headers,
            params=encrypted_query_dict if query_dict else None,
            data=encrypted_body_str if encrypted_body_str else None,
        )

        response_json = await response.json()

        if response_json.get("state") == "S":
            if "checkVersion" in uri:
                return self.__decrypt_payload_using_app_code(
                    response_json["payload"], app_code
                )
            else:
                decrypted_payload = self.__decrypt_payload_using_key(
                    response_json["payload"]
                )
                self.logger.debug("Response payload: %s", decrypted_payload)
                return decrypted_payload
        elif response_json.get("errorCode") == 600001:
            raise MazdaAPIEncryptionException("Server rejected encrypted request")
        elif response_json.get("errorCode") == 600002:
            raise MazdaTokenExpiredException("Token expired")
        elif (
            response_json.get("errorCode") == 920000
            and response_json.get("extraCode") == "400S01"
        ):
            raise MazdaRequestInProgressException(
                "Request already in progress, please wait and try again"
            )
        elif (
            response_json.get("errorCode") == 920000
            and response_json.get("extraCode") == "400S11"
        ):
            raise MazdaException(
                "The engine can only be remotely started 2 consecutive times. "
                "Please drive the vehicle to reset the counter."
            )
        elif "error" in response_json:
            raise MazdaException("Request failed: " + response_json["error"])
        else:
            raise MazdaException("Request failed for an unknown reason")

    async def __ensure_keys_present(self):
        if self.enc_key is None or self.sign_key is None:
            await self.__retrieve_keys()

    async def __ensure_token_is_valid(self):
        await self.ensure_token_valid()

    async def __retrieve_keys(self):
        self.logger.info("Retrieving encryption keys")
        response = await self.api_request(
            "POST", "service/checkVersion", needs_keys=False, needs_auth=False
        )
        self.logger.info("Successfully retrieved encryption keys")
        self.enc_key = response["encKey"]
        self.sign_key = response["signKey"]

    async def login(self):
        """For OAuth2, login means ensuring the token is valid."""
        await self.ensure_token_valid()

    async def close(self):
        """No-op since websession is managed externally."""
