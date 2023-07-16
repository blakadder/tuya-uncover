# tuya-uncover

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/S6S650JEK) &emsp; <a href="https://paypal.me/tasmotatemplates"><img src="https://img.shields.io/static/v1?logo=paypal&label=&message=Donate via PayPal&color=slategrey"></a>

A simple Python script to list devices from Tuya OEM apps and reveal their local keys and [Data Points](https://developer.tuya.com/en/docs/iot-device-dev/tuyaos-gateway-device-datapoint?id=Kc80mqozruc72) it uses.

Supports these apps:

- Smart Life (default)
- Tuya
- BirdLover
- Brennenstuhl
- Gosund
- Ledvance
- Proscenic
- Sylvania
- Ultenic

*Not all apps are verified as working since some keys were found randomly on the internet.*

Goes well with [make-all/tuya-local](https://github.com/make-all/tuya-local) Home Assistant custom component.

## Use

Requires Python installed!

```shell
uncover.py -v vendor username password
```

`uncover.py` -h for help

### Requirements

```shell
pip install requests
```

And maybe more... Let me know!

## Thanks to

Main code from [@aavatar gist](https://gist.github.com/avataar/2a6ee4f58aaedfcc062a838380f3cffb).

App secrets deciphered with instructions from [https://blog.rgsilva.com/reverse-engineering-positivos-smart-home-app/](https://blog.rgsilva.com/reverse-engineering-positivos-smart-home-app/) and <https://github.com/nalajcie/tuya-sign-hacking>

Some keys found on [rospogrigio/localtuya](https://github.com/rospogrigio/localtuya/issues/1188)
