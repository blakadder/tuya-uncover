import hashlib
import hmac
import unittest
from unittest.mock import Mock, patch

import uncover


class OEMTests(unittest.TestCase):
    def setUp(self):
        self.session_patch = patch("uncover.requests.session")
        self.session = self.session_patch.start().return_value
        self.addCleanup(self.session_patch.stop)
        self.time_patch = patch("uncover.time.time", return_value=1700000000)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)

    def api(self, vendor, region="eu", country_code=""):
        return uncover.TuyaCloudApiOEM(
            "oem_" + vendor, region, "user@example.com", "test-password",
            "generic-client", "generic-secret", country_code,
        )

    def respond(self, *results):
        self.session.post.side_effect = [
            Mock(json=Mock(return_value={"success": True, "result": result}))
            for result in results
        ]

    def test_boneco_login_and_device_retrieval(self):
        api = self.api("boneco", country_code="48")
        device = {
            "name": "H700 SMART", "devId": "test-device", "localKey": "test-local-key",
            "category": "jsq", "uuid": "test-uuid", "productId": "test-product",
            "dps": {"1": True}, "mac": "001122334455", "virtual": False,
            "iconUrl": "https://example.com/icon.png",
        }
        self.respond(
            {"publicKey": str(2**2048 - 159), "exponent": "65537", "token": "test-token"},
            {"sid": "test-session"}, [{"groupId": 123}], [device],
        )
        api.login()
        devices = api.list_devices(map_tt_compat=True, include_raw=True)
        calls = self.session.post.call_args_list
        self.assertEqual([call.kwargs["data"]["a"] for call in calls], [
            "thing.m.user.email.token.create", "thing.m.user.email.password.login",
            "thing.m.location.list", "thing.m.my.group.device.list",
        ])
        for call in calls:
            self.assertEqual(call.args[0], "https://a1-eu.boneco-smart-app.com/api.json")
            self.assertEqual(call.kwargs["params"], {})
            self.assertEqual(call.kwargs["data"]["chKey"], api._request_params["chKey"])
        self.assertEqual(calls[0].kwargs["data"]["postData"],
                         '{"countryCode":"48","email":"user@example.com"}')
        self.assertNotIn("sid", calls[1].kwargs["data"])
        self.assertEqual(calls[2].kwargs["data"]["sid"], "test-session")
        self.assertEqual(calls[3].kwargs["data"]["gid"], 123)
        self.assertEqual(devices[0]["key"], "test-local-key")
        self.assertEqual(devices[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(devices[0]["raw"], device)

    def test_boneco_signature_matches_canonical_request(self):
        api = self.api("boneco")
        self.respond([])
        api._sid = "test-session"
        api._api("tuya.m.location.list", extra_params={"gid": 123})
        body = self.session.post.call_args.kwargs["data"]
        canonical = (
            "a=thing.m.location.list||appVersion=1.1.0||chKey=" + body["chKey"]
            + "||clientId=" + api._client_id + "||os=Android||sid=test-session"
            + "||time=1700000000||ttid=sdk_bonecosmart@" + api._client_id + "||v=1.0"
        )
        expected = hmac.new(api._secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(body["sign"], expected)

    def test_existing_and_generic_vendors_keep_legacy_requests(self):
        for vendor in ("smartlife", "ledvance", "generic"):
            with self.subTest(vendor=vendor):
                api = self.api(vendor)
                self.respond({"token": "test-token"})
                api._api("tuya.m.user.email.token.create", {"email": "user@example.com"},
                         requires_sid=False)
                call = self.session.post.call_args
                self.assertEqual(call.args[0], "https://a1.tuyaeu.com/api.json")
                self.assertEqual(call.kwargs["params"]["a"], "tuya.m.user.email.token.create")
                self.assertNotIn("chKey", call.kwargs["params"])
                self.assertEqual(call.kwargs["data"], {"postData": '{"email":"user@example.com"}'})

    def test_boneco_regions(self):
        for region in ("eu", "us", "in"):
            with self.subTest(region=region):
                self.assertEqual(self.api("boneco", region)._endpoint,
                                 f"https://a1-{region}.boneco-smart-app.com/api.json")
        with self.assertRaisesRegex(ValueError, "Region cn is not supported"):
            self.api("boneco", "cn")


if __name__ == "__main__":
    unittest.main()
