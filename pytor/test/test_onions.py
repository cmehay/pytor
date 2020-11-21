import os
from base64 import b64decode

import pytest

from ..onion import OnionV2
from ..onion import OnionV3


class _testOnion:

    private_key = None
    public_key = None
    onion_hostname = None
    onion_cls = None
    version = None

    check_method = {
        "priv": "get_private_key",
        "pub": "get_public_key",
        "onion": "onion_hostname",
    }

    def generate_new_key(self):
        return self.onion_cls().get_private_key()

    def test_import_key(self):
        o = self.onion_cls(private_key=self.private_key)
        assert o.get_public_key() == self.public_key
        assert o.onion_hostname == self.onion_hostname
        assert o.get_private_key() == self.private_key

    def test_generate_key(self):
        o = self.onion_cls()
        assert o.onion_hostname.endswith(".onion")
        assert len(o.onion_hostname) == len(self.onion_hostname)

    def test_import_file(self, fs):
        path = os.path.join("/test_tor", self.files["priv"])
        fs.create_file(path, contents=self.private_key)

        o = self.onion_cls()
        path = os.path.join("/test_tor", self.files["priv"])
        with open(path, "rb") as f:
            o.set_private_key_from_file(f)
        assert o.onion_hostname == self.onion_hostname

    def test_import_hidden_directory(self, tmpdir):
        d = tmpdir.mkdir("hidden_directory")
        f = d.join(self.files["priv"])
        f.write_binary(self.private_key)
        o = self.onion_cls(hidden_service_path=d)
        assert o.onion_hostname == self.onion_hostname

    def test_write_hidden_directory(self, tmpdir):
        d = tmpdir.mkdir("hidden_directory")
        o = self.onion_cls(private_key=self.private_key)
        o.write_hidden_service(path=str(d))

        for file_type, file in self.files.items():
            method = getattr(o, self.check_method[file_type])
            check = method() if callable(method) else method
            check = check.encode() if isinstance(check, str) else check
            assert d.join(file).read_binary() == check

    def test_import_empty_hidden_directory(self, tmpdir):
        d = tmpdir.mkdir("hidden_directory")
        o = self.onion_cls(hidden_service_path=d)
        o.write_hidden_service()
        assert d.join(self.files["priv"]).read_binary() == o.get_private_key()
        assert d.join(self.files["onion"]).read() == o.onion_hostname

    def test_import_hidden_directory_with_new_key(self, tmpdir):
        d = tmpdir.mkdir("hidden_directory")
        f = d.join(self.files["priv"])
        f.write_binary(self.generate_new_key())
        o = self.onion_cls(hidden_service_path=d, private_key=self.private_key)
        with pytest.raises(Exception):
            o.write_hidden_service()
        o.write_hidden_service(force=True)
        assert d.join(self.files["priv"]).read_binary() == o.get_private_key()
        assert d.join(self.files["onion"]).read() == o.onion_hostname

    def test_version(self):
        assert self.onion_cls().version == str(self.version)


class TestOnionV2(_testOnion):

    private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCsMP4gl6g1Q313miPhb1GnDr56ZxIWGsO2PwHM1infkbhlBakR
6DGQfpE31L1ZKTUxY0OexKbW088v8qCOfjD9Zk1i80JP4xzfWQcwFZ5yM/0fkhm3
zLXqXdEahvRthmFsS8OWusRs/04U247ryTm4k5S0Ch5OTBuvMLzQ8W0yDwIDAQAB
AoGAAZr3U5B2ZgC6E7phKUHjbf5KMlPxrDkVqAZQWvuIKmhuYqq518vlYmZ7rhyS
o1kqAMrfH4TP1WLmJJlLe+ibRk2aonR4e0GbW4x151wcJdT1V3vdWAsVSzG3+dqX
PiGT//DIe0OPSH6ecI8ftFRLODd6f5iGkF4gsUSTcVzAFgkCQQDTY67dRpOD9Ozw
oYH48xe0B9NQCw7g4NSH85jPurJXnpn6lZ6bcl8x8ioAdgLyomR7fO/dJFYLw6uV
LZLqZsVbAkEA0Iei3QcpsJnYgcQG7l5I26Sq3LwoiGRDFKRI6k0e+en9JQJgA3Ay
tsLpyCHv9jQ762F6AVXFru5DmZX40F6AXQJBAIHoKac8Xx1h4FaEuo4WPkPZ50ey
dANIx/OAhTFrp3vnMPNpDV60K8JS8vLzkx4vJBcrkXDSirqSFhkIN9grLi8CQEO2
l5MQPWBkRKK2pc2Hfj8cdIMi8kJ/1CyCwE6c5l8etR3sbIMRTtZ76nAbXRFkmsRv
La/7Syrnobngsh/vX90CQB+PSSBqiPSsK2yPz6Gsd6OLCQ9sdy2oRwFTasH8sZyl
bhJ3M9WzP/EMkAzyW8mVs1moFp3hRcfQlZHl6g1U9D8=
-----END RSA PRIVATE KEY-----
    """.strip().encode()

    public_key = b64decode(
        """
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCsMP4gl6g1Q313miPhb1GnDr56
ZxIWGsO2PwHM1infkbhlBakR6DGQfpE31L1ZKTUxY0OexKbW088v8qCOfjD9Zk1i
80JP4xzfWQcwFZ5yM/0fkhm3zLXqXdEahvRthmFsS8OWusRs/04U247ryTm4k5S0
Ch5OTBuvMLzQ8W0yDwIDAQAB
    """
    )
    onion_hostname = "wcet3bgkj4purdfx.onion"
    onion_cls = OnionV2
    files = {
        "priv": "private_key",
        "onion": "hostname",
    }

    version = 2


class TestOnionV3(_testOnion):

    private_key = b64decode(
        """
PT0gZWQyNTUxOXYxLXNlY3JldDogdHlwZTAgPT0AAACArobDQYyZAWXei4QZwr++j96H1X/gq14N
wLRZ2O5DXuL0EzYKkdhZSILY85q+kfwZH8z4ceqe7u1F+0pQi/sM
    """
    )

    public_key = b64decode(
        """
PT0gZWQyNTUxOXYxLXB1YmxpYzogdHlwZTAgPT0AAAC9kzftiea/kb+TWlCEVNpfUJLVk+rFIoMG
m9/hW13isA==
    """
    )

    onion_hostname = (
        "xwjtp3mj427zdp4tljiiivg2l5ijfvmt5lcsfaygtpp6cw254kykvpyd.onion"
    )

    onion_cls = OnionV3
    files = {
        "priv": "hs_ed25519_secret_key",
        "pub": "hs_ed25519_public_key",
        "onion": "hostname",
    }
    version = 3
