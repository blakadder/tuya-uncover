# tuya-uncover

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S6S650JEK) &emsp; <a href="https://paypal.me/tasmotatemplates"><img src="https://img.shields.io/static/v1?logo=paypal&label=&message=Donate via PayPal&color=slategrey"></a>

A simple Python script to list devices from Tuya OEM apps and reveal their local keys and [Data Points](https://developer.tuya.com/en/docs/iot-device-dev/tuyaos-gateway-device-datapoint?id=Kc80mqozruc72) it uses.

Supports these vendors/apps:

- Smart Life (default)
- Tuya
- Boneco Smart
- BirdLover
- Brennenstuhl
- Gosund
- Ledvance
- Proscenic
- Sylvania
- Ultenic
- Tesla
- LSC Smart Connect
- Philips Smart Select
- AlecoAir
- Nous Smart
- Nedis Smartlife
- Blitzwolf
- Airam SmartHome
- Teratlife
- Setti+
- Overmax Control
- Artika
- Xtreme Connected Home
- Atomi Smart
- Cree Lighting

*Not all apps are verified as working since some keys were found randomly on the internet.*

Goes well with [make-all/tuya-local](https://github.com/make-all/tuya-local) Home Assistant custom component.

## Use

Requires Python installed!

```shell
uncover.py -v vendor username password
```

`uncover.py -h` for all options

### Boneco Smart

Boneco Smart uses its own API endpoints and an updated request-signing format.
Select `boneco` and provide the country calling code used for your app account:

```shell
python uncover.py -v boneco -r eu --country-code 48 'you@example.com' 'your-password'
```

The app credentials were extracted from the official `com.boneco.smart` Android
app version 1.1.0. Login and local-key retrieval were verified with an H700 SMART
on the EU endpoint. The app also supplies endpoints for `us` and `in`; these have
not been live-tested. The `cn` region is not supported for this vendor.

Passwords using special characters might need to be escaped in `"` (e.g. `python uncover.py -r eu -v ledvance test@test.com "my$pass@word&"`

### Requirements

```shell
pip install requests
```

And maybe more... Let me know!

## Thanks to

Main code from [@avataar gist](https://gist.github.com/avataar/2a6ee4f58aaedfcc062a838380f3cffb).

App secrets deciphered with instructions from [https://rgsilva.com/blog/reverse-engineering-positivos-smart-home-app/](https://rgsilva.com/blog/reverse-engineering-positivos-smart-home-app/) and <https://github.com/nalajcie/tuya-sign-hacking>

Some keys found on [rospogrigio/localtuya](https://github.com/rospogrigio/localtuya/issues/1188)
