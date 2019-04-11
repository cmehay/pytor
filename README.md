# pytor

`pytor` is a simple python librairy to create and manager tor hidden services in version 2 and 3.

```sh
$ pytor new
hostname:
cljfodghi4w5frc6.onion
private_key:
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQD2Gza8HXzgDGo+YwyhjOdgD0GY7ti5en8YGXtcsBi/JIwHdKZo
iLC4e5pWzlmB2ACdTw93ASFTGpPFs7nRxk4NuXo1BnvTsqzzcrsd9HV6xuKO7BkS
aTEY3tgrSvB2nQtM1WR9FQoyxV+EWeE0Q9vrBVpEizO4kHqFXRanOJpJbwIDAQAB
AoGAA/axPXteGP+qMGIJAIsT6OSmAlAKdoZGCL3UUkxVwbJVfQNAcNuOuRHojPBa
2bAAZogw8BI5Fq0NZzg7TGkctazKbvrmIx6o22spx2MOQXEc7lj3R3CJ8B+F1moz
9lNxIhNmw4bHeL3Sw5XMTPnOhCy1OKmouWrrcOj7B59YKrkCQQD2pWkZih6Ijl0y
xG3vB8w22krpe0YOne94aXwdggkji6Cfne8YRNWU9y8FvxGZgwfXZKwGCOSOgq7r
0SP7vEoZAkEA/3CP8BGY1jThrLHLWNPKm5Vu1+YZClL4ibs4cdtxIs0J0l+dQcYW
LMSkQpOy1C/nIIYPJpq9x8sCXG2BsRgwxwJAR9NhqONVAvVaZKdZUEuYB71IJXgV
rboGe61UTI+Ks8Q8kV7/urSI8imNkwHSUT8cMHiLs/IxBOM/p0KvVOa/OQJAHlXY
0jLUysOW9XJb6t2kFxwFAODTonU+DOVOC796zR46h2BRhaknowNrWni96RMTSLqC
/BuuZBbI3f8nQsfTqwJBAMX/KjXO/MqcB8TAjyKWHNyVR4T8OJM5lgbk8IGLKE5/
w96jWD0AEePqKKdWofLImi074zMSyMKuu6RFrkBSUuI=
-----END RSA PRIVATE KEY-----
```

```
$ mkdir test
$ pytor new-hidden-service test --version 3
FYI: Binary data is base64 encoded
path:
test
hostname:
byb3bkhwi2ccbrctsqkowckpvk3tok36geddzg4l2m6yn6mrw626nqid.onion
hs_ed25519_secret_key:
PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAAAwIFsWaVtOk8r3RvXnkZcmxwIaDmmOdV8D7KaVf6yBWjVUIUTPpOWNQ9+hEiPKUclJ1RpflZ9FSdPgSj0j0tE3
hs_ed25519_public_key:
PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAAOA7Co9kaEIMRTlBTrCU+qtzcrfjEGPJuL0z2G+ZG3tQ==
```

(more doc soon, I'm tired right mow ~)
