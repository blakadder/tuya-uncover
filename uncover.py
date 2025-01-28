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
        "secret": "A_ag4xcmp9rjttkj9yf9e8c3wfxry7yr44_wparh3scdv8dc7rrnuegaf9mqmn4snpk"
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
    },
    "woox": {
        "brand": "Woox Home",
        "client_id": "pyxevcmw83jg83qca9c7",
        "secret": "A_e3g9q4enqeew9x7xgcqkn8jjcdgwf8py_h8wv7dea7u4hnfc8k8qagr897yuc79ar",
    },
    "maxcom": {
        "brand": "Maxcom Home",
        "client_id": "83f54m7c4wpmp48a377e",
        "secret": "A_n33asm4fv3yud9pcjfuxcycspy7fhx3g_kvjavqmjyf3v5wk9s55fgeewgkgjnhc9",
    },
    "calex": {
        "brand": "Calex Smart",
        "client_id": "xh8txuxq9juy48e5q39w",
        "secret": "A_u7mn44dkwx3qqe4kkakc4p933au5fnkr_g9egj8jjgup8ctpxjknye5ar4wxghesa",
    },
    "smartdgm": {
        "brand": "SmartDGM",
        "client_id": "ryvgvwmtydwvsh3hd7rr",
        "secret": "A_gmjvan774aag5u8ksjtt8dvyas8pvg8j_g3xtrhk4rxpeqxuneqmrx54dqy4htda3",
    },
    "gridconnect": {
        "brand": "GridConnect",
        "client_id": "k584ttaqt7f4huakhtgp",
        "secret": "A_yg7pds9ap4vd3vj8t8cjy5agvj4jygay_c5t98m3kp7atcnspggcqewp5cqhnfuum",
    },
    "spectrum": {
        "brand": "Spectrum Smart",
        "client_id": "t8aygqqdh8u7nd5j5kcf",
        "secret": "A_avfpxsmwwt9txxg8eyd4pppfdqdyydqg_xsxdsvwgt7kdpe8xj38nvkxw4gaw4dkh",
    },
    "tesla": {
        "brand": "Tesla Smart",
        "client_id": "gwfwneqcq8xhqghp47wq",
        "secret": "A_3kfxrauppxvtrmknr4mxatacdf7yvmfg_hrwpnqjag5jp3mkcsm59agm8u5dfuxka",
    },
    "lscsmartconnect": {
        "brand": "LSC Smart Connect",
        "client_id": "q594qaqdpy89gmvyndtp",
        "secret": "A_yegjfwuukevd8qfxw3rjfr5sj43p5gpr_xh59e8qykn4sp7jyh7rwaq3ykfwf8e5n",
    },
    "alecoair": {
        "brand": "AlecoAir",
        "client_id": "pvufcdrftnfkt4rqkxs5",
        "secret": "A_48vafqcmrfx4mvjrph4j4ayfe9hctnkd_jmehruant8ag7nscxn8u47u9yf8h48e7",
    },
    "philipssmartselect": {
       "brand": "Philips Smart Select",
       "client_id": "ajc33deua7sey8gkg8st",
       "secret": "A_995k5m8tpah4snp7xu59mcvmfhkhv7mk_kts7cj7mrxgjv7nqcjp9wata3t7ehwya",
    },
    "noussmart": {
       "brand": "Nous Smart",
       "client_id": "dhs3xggvwehvc5tj9xqp",
       "secret": "A_wwwrnvy7gayy9dvp5nuahyd5d3j4kyxp_7vgwxdy589jtwwee7rugayxrderkekww",
    },
    "nedis": {
       "brand": "Nedis Smartlife",
       "client_id": "pettfwyepwpwwhxy57gp",
       "secret": "A_73p8kvkhsted5fxvx8pfudk5hwtmnjr3_yptwxx4t9rkmcppyagwpd43y77tnpw8s",
    },
    "blitzwolf": {
       "brand": "Blitzwolf",
       "client_id": "xpqw7hnghsyvt7y84qr3",
       "secret": "A_yf3skmg73upyytecsy5tjg58tdmh87t3_vgq3jywdfa8kqyr7eaq7cgm387e53ew9",
    },
    "airam": {
       "brand": "Airam SmartHome",
       "client_id": "efaxsa7hyadmwvw89mvj",
       "secret": "A_c8cse843mexx8umvdsrqfmx3hs47fk93_jm5tdcyv8hr4kdfq8mxkvf9hj59pte3j",
    },
    "treatlife": {
       "brand": "Treatlife",
       "client_id": "8yncru89qa8495mdutya",
       "secret": "A_37enmfsnr4r3w8j5cd3fxmhm97gaatxx_y4gn37gryf5ufqhqgh99r9wp3h44dp95"
    },
    "settiplus": {
       "brand": "Setti+",
       "client_id": "8fjupshhjwqq4auxtd4m",
       "secret": "A_4eqrx7y3sygqv5eragnwxnetv3epsj4f_svhcum73wnvaehgv88wdj5dddfxrt48u"
    },
    "overmax": {
       "brand": "Overmax Control",
       "client_id": "um7ysycqag83et8drf8n",
       "secret": "A_jpjmj4vp5gvwmdpf8hk5yjkrj3teegve_kwqsmrup5qrx4rpgssrkt7dngq8c53q9"
    },
    "artika": {
       "brand": "Artika",
       "client_id": "7htkwyyja9h3yuh9w7qj",
       "secret": "A_gyw7grhscq9ewwmdhygnchqattuyyapy_kvfa8gtvuu9fdetpvt99443gy4h34pqk"
    },
    "xch2023": {
       "brand": "Xtreme Connected Home",
       "client_id": "4jgkenx3w5gpfuh9mfux",
       "secret": "A_k3cwmej33schtsu75drn75gjrvyqrspd_ernnu7n85ynkmnesvn4hpvqdjy5rqatr"
    },
    "creelighting": {
       "brand": "Cree Lighting",
       "client_id": "yaus4vykgfgnaum75h8c",
       "secret": "A_pws4aa9ux4dhrvwxgj37pptsgu9dys8q_3wqevmkewf7kqum3dm79tjjg7asqw9dc"
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

    def list_devices(self, map_tt_compat=False, include_raw=False):
        devs = [] if map_tt_compat else {}
        # First fetch all "groups", i.e. homes
        for group in self._api("tuya.m.location.list"):
            # Then fetch devices for each group and merge into a single list
            for dev in self._api(
                "tuya.m.my.group.device.list", extra_params={"gid": group["groupId"]}
            ):
                if map_tt_compat:
                    # Map each device to the same format as TinyTuya's devices.json
                    d = self._map_device_tt(dev)
                    if include_raw:
                        d['raw'] = dev
                    devs.append(d)
                else:
                    # Map each device to the same format as the IoT Platform API
                    k = dev["name"]
                    devs[k] = self._map_device(dev)
                    if include_raw:
                        devs[k]['raw'] = dev
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

    def _map_device_tt(self, dev):
        return {
            "name": dev["name"],
            "id": dev["devId"],
            "key": dev["localKey"],
            "mac": ':'.join(dev["mac"][i:i+2] for i in range(0, len(dev["mac"]), 2)),
            "uuid": dev["uuid"],
            "category": dev["category"],
            "product_id": dev["productId"],
            "sub": dev["virtual"],
            "icon": dev["iconUrl"]
        }

class InvalidUserSession(ValueError):
    """Invalid user session error."""


class InvalidAuthentication(ValueError):
    """Invalid authentication error."""


def main(args):
    api = TuyaCloudApiOEM(f"oem_{args.vendor}", args.region, args.email,
                          args.password, args.client_id, args.secret)

    if args.sid:
        api._sid = args.sid
    else:
        api.login()
        print( 'Got Login SID:', api._sid )

    devs = api.list_devices(bool(args.write_json), bool(args.raw_details))
    print('Downloaded %r devices:' % len(devs))
    print(json.dumps( devs, indent=4))

    if args.write_json:
        try:
            # Load existing devices
            with open(args.write_json, 'r') as f:
                all_old_devs = json.load(f)
            new_devids = [d['id'] for d in devs]
            devs += [d for d in all_old_devs if d['id'] not in new_devids]
        except:
            print('Unable to load existing devices from', args.write_json)

        # Sort it by id
        devs.sort( key=lambda dev: dev['id'] if 'id' in dev else '' )
        with open(args.write_json, 'w') as f:
            json.dump(devs, f, indent=4, default=dict)
        print('Saved %r device list to:' % len(devs), args.write_json)


parser = argparse.ArgumentParser(description='List devices via the Tuya OEM API.')

parser.add_argument("email", help="Your Tuya OEM app account email")

parser.add_argument("password", help="Your Tuya OEM app password")

parser.add_argument("-i", "--sid", "--session-id",
                    default="",
                    help="Previous session ID")

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

parser.add_argument("-a", "--raw-details",
                    action='store_true',
                    help="Include raw output in 'raw' key")

parser.add_argument("-w", "--write-json",
                    nargs='?', const='devices.json', default=False, metavar='devices.json',
                    help="Write output to TinyTuya-compatible devices.json file. If this file already exists then devices will be merged into it")

args = parser.parse_args()
print(args)
main(args)
