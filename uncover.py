import argparse
import functools
import logging
import hmac
import hashlib
import json

import requests
import time

_TUYA_USER_AGENT = "TY-UA=APP/Android/1.1.6/SDK/null"
_TUYA_API_VERSION = "1.0"

_TUYA_KNOWN_VENDORS = {
    "birdlover": {
        "brand": "BirdLover",
        "client_id": "gmusrthh3sygeyv3sr38",
        "secret": "A_x4y4ds9nysv4d3agjyqwmvnptwhgtcwu_pku4cchspfmskfgtaacqcvkfdscx7u7t",
    },
    "brennenstuhl": {
        "brand": "Brennenstuhl",
        "client_id": "dh35afm9ha79sppyxgkf",
        "secret": "A_aqy9p3e78xr5htpsn95fss5rvcdtaahd_9gyrek4h5ygwshsndqurwjkddtjpw9yr",
    },
    "gosund": {
        "brand": "Gosund",
        "client_id": "pwhnn4fa7ydkakf3nehn",
        "secret": "A_pqdyxyx3uhk337sxxumdgfry3awaxysm_wm8hvxahqhcvvnpqgurympm4ppfgxxnm",
    },
    "ledvance": {
        "brand": "Ledvance",
        "client_id": "fx3fvkvusmw45d7jn8xh",
        "secret": "A_armptsqyfpxa4ftvtc739ardncett3uy_cgqx3ku34mh5qdesd7fcaru3gx7tyurr",
    },
    "proscenic": {
        "brand": "Proscenic",
        "client_id": "ja9ntfcxcs8qg5sqdcfm",
        "secret": "A_4vgq3tcqnam9drtvgam8hneqjprtjnf4_c5rkn5tga889whe5cd7pc9j387knwsuc"
    },
    "smartlife": {
        "brand": "Smart Life",
        "client_id": "ekmnwp9f5pnh3trdtpgy",
        "secret": "0F:C3:61:99:9C:C0:C3:5B:A8:AC:A5:7D:AA:55:93:A2:0C:F5:57:27:70:2E:A8:5A:D7:B3:22:89:49:F8:88:FE_jfg5rs5kkmrj5mxahugvucrsvw43t48x_r3me7ghmxjevrvnpemwmhw3fxtacphyg"
    },
    "sylvania": {
        "brand": "Sylvania",
        "client_id": "creq75hn4vdg5qvrgryp",
        "secret": "A_wparh3scdv8dc7rrnuegaf9mqmn4snpk_ag4xcmp9rjttkj9yf9e8c3wfxry7yr44"
    },
    "tuya": {
        "brand": "Tuya",
        "client_id": "3fjrekuxank9eaej3gcx",
        "secret": "93:21:9F:C2:73:E2:20:0F:4A:DE:E5:F7:19:1D:C6:56:BA:2A:2D:7B:2F:F5:D2:4C:D5:5C:4B:61:55:00:1E:40_aq7xvqcyqcnegvew793pqjmhv77rneqc_vay9g59g9g99qf3rtqptmc3emhkanwkx"
    },
    "ultenic": {
        "brand": "Ultenic",
        "client_id": "jumhahnc744wvtaj9qgd",
        "secret": "A_jeer4x97qvjhcx7dmxxasst49gya4mn3_dfpfvmmm9sgjfmydrtakcmu38mu3jctv"
    }
}

_LOGGER = logging.getLogger(__name__)


class TuyaCloudApiOEM():
    def __init__(
        self,
        cloud_type: str,
        region: str,
        username: str,
        password: str,
        client_id: str,
        secret: str,
    ):
        self._endpoint = f"https://a1.tuya{region}.com/api.json"
        self._username = username
        self._password = password

        # It works with empty country code but the parameter must be sent nonetheless
        self._country_code = ""

        if cloud_type.startswith("oem_"):
            vendor = cloud_type.replace("oem_", "")
        else:
            raise ValueError("Cloud type must be one of the oem_xxx types")

        if vendor in _TUYA_KNOWN_VENDORS:
            self._client_id = _TUYA_KNOWN_VENDORS[vendor]["client_id"]
            self._secret = _TUYA_KNOWN_VENDORS[vendor]["secret"]
            self._brand = _TUYA_KNOWN_VENDORS[vendor]["brand"]
        elif vendor == "generic":
            self._client_id = client_id
            self._secret = secret
            self._brand = "generic"
        else:
            raise ValueError(f"Unknown vendor {vendor}")

        self._session = requests.session()
        self._sid = None

    def _api(
        self, action, payload=None, extra_params=None, requires_sid=True
    ):
        headers = {"User-Agent": _TUYA_USER_AGENT}

        if extra_params is None:
            extra_params = {}

        params = {
            "a": action,
            "clientId": self._client_id,
            "v": _TUYA_API_VERSION,
            "time": str(int(time.time())),
            **extra_params,
        }

        if requires_sid:
            if self._sid is None:
                raise ValueError("You need to login first.")
            params["sid"] = self._sid

        data = {}
        if payload is not None:
            data["postData"] = json.dumps(payload, separators=(",", ":"))

        params["sign"] = self._sign({**params, **data})

        func = functools.partial(
            self._session.post,
            self._endpoint,
            params=params,
            data=data,
            headers=headers,
        )

        _LOGGER.debug("Request: headers %s, params %s, data %s", headers, params, data)

        result = func()
        result = self._handle(result.json())

        _LOGGER.debug("Result: %s", result)

        return result

    def _sign(self, data):
        keys_not_to_sign = ["gid"]

        sorted_keys = sorted(list(data.keys()))

        # Create string to sign
        str_to_sign = ""
        for key in sorted_keys:
            if key in keys_not_to_sign:
                continue
            if key == "postData":
                if len(str_to_sign) > 0:
                    str_to_sign += "||"
                str_to_sign += key + "=" + self._mobile_hash(data[key])
            else:
                if len(str_to_sign) > 0:
                    str_to_sign += "||"
                str_to_sign += key + "=" + data[key]

        return hmac.new(
            bytes(self._secret, "utf-8"),
            msg=bytes(str_to_sign, "utf-8"),
            digestmod=hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _mobile_hash(data):
        prehash = hashlib.md5(bytes(data, "utf-8")).hexdigest()
        return prehash[8:16] + prehash[0:8] + prehash[24:32] + prehash[16:24]

    @staticmethod
    def _handle(result):
        if result["success"]:
            return result["result"]
        if result["errorCode"] == "USER_SESSION_INVALID":
            raise InvalidUserSession(result["errorMsg"])
        if result["errorCode"] == "USER_PASSWD_WRONG":
            raise InvalidAuthentication(result["errorMsg"])
        raise ValueError(f"{result['errorMsg']} ({result['errorCode']})")

    @staticmethod
    def _plain_rsa_encrypt(modulus, exponent, message):
        """Encrypt message using plain (textbook) RSA encrypt."""
        message_int = int.from_bytes(message, "big")
        enc_message_int = pow(message_int, exponent, modulus)
        return enc_message_int.to_bytes(256, "big")

    def _enc_password(self, modulus, exponent, password):
        passwd_hash = hashlib.md5(password.encode("utf8")).hexdigest().encode("utf8")
        return self._plain_rsa_encrypt(int(modulus), int(exponent), passwd_hash).hex()

    def login(self):
        payload = {"countryCode": self._country_code, "email": self._username}
        token_info = self._api(
            "tuya.m.user.email.token.create", payload, requires_sid=False
        )

        payload = {
            "countryCode": self._country_code,
            "email": self._username,
            "ifencrypt": 1,
            "options": '{"group": 1}',
            "passwd": self._enc_password(
                token_info["publicKey"], token_info["exponent"], self._password
            ),
            "token": token_info["token"],
        }
        login_info = self._api(
            "tuya.m.user.email.password.login", payload, requires_sid=False
        )

        self._sid = login_info["sid"]

    def list_devices(self):
        devs = {}
        # First fetch all "groups", i.e. homes
        for group in self._api("tuya.m.location.list"):
            # Then fetch devices for each group and merge into a single list
            for dev in self._api(
                "tuya.m.my.group.device.list", extra_params={"gid": group["groupId"]}
            ):
                # Map each device to the same format as the IoT Platform API
                devs[dev["name"]] = self._map_device(dev)
                # print(devs)
        return devs

    def _map_device(self, dev):
        return {
            # "name": dev["name"],
            "id": dev["devId"],
            "local_key": dev["localKey"],
            "category": dev["category"],
            "uuid": dev["uuid"],
            "product_id": dev["productId"],
            "dps": dict(sorted(dev["dps"].items())),
        }

class InvalidUserSession(ValueError):
    """Invalid user session error."""


class InvalidAuthentication(ValueError):
    """Invalid authentication error."""


def main(args):
    api = TuyaCloudApiOEM(f"oem_{args.vendor}", args.region, args.email,
                          args.password, args.client_id, args.secret)

    api.login()
    print(json.dumps(api.list_devices(), indent=4))


parser = argparse.ArgumentParser(description='List devices via the Tuya OEM API.')

parser.add_argument("-r", "--region", choices=["eu", "us", "cn", "in"],
                    default="eu",
                    help="The region to use (default is eu)")

parser.add_argument("-v", "--vendor", choices=list(_TUYA_KNOWN_VENDORS.keys()),
                    default="smartlife",
                    help="The OEM vendor to use (default is Smart Life)")

parser.add_argument("-c", "--client-id",
                    default="",
                    help="Tuya OEM vendor client ID, required for generic vendor")

parser.add_argument("-s", "--secret",
                    default="",
                    help="Tuya OEM vendor secret, required for generic vendor")

parser.add_argument("email", help="Your Tuya OEM app account email")

parser.add_argument("password", help="Your Tuya OEM app password")

args = parser.parse_args()

main(args)