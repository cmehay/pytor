import os
import re
import warnings
from abc import ABC
from abc import abstractmethod
from base64 import b32encode
from base64 import b64encode
from hashlib import sha1
from hashlib import sha3_256
from hashlib import sha512
from typing import BinaryIO

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from .ed25519 import Ed25519


__all__ = [
    "OnionV2",
    "OnionV3",
    "EmptyDirException",
    "NonEmptyDirException",
]


class EmptyDirException(Exception):
    pass


class NonEmptyDirException(Exception):
    pass


class Onion(ABC):
    """
    Interface to implement hidden services keys managment
    """

    _priv = None
    _pub = None
    _hidden_service_path = None
    _priv_key_filename = None
    _pub_key_filename = None
    _host_filename = None
    _version = None

    def __init__(
        self, private_key: bytes = None, hidden_service_path: str = None
    ):
        if self._version == 2:
            warnings.warn(
            "Onion addresses version 2 are not supported anymore by tor",
            UserWarning
        )

        if hidden_service_path:
            try:
                self.load_hidden_service(hidden_service_path)
            except EmptyDirException:
                pass
            self._hidden_service_path = hidden_service_path
        if private_key:
            self.set_private_key(private_key)
        if not self._priv:
            self.gen_new_private_key()

    @abstractmethod
    def gen_new_private_key(self) -> None:
        "Generate new private key"
        ...

    def set_private_key_from_file(self, file: BinaryIO):
        "Load private key from file"
        self.set_private_key(file.read())

    @abstractmethod
    def set_private_key(self, key: bytes) -> None:
        "Add private key"
        ...

    @abstractmethod
    def _save_keypair(self, key) -> None:
        "Generate pub key from priv key and save both in instance"
        ...

    def load_hidden_service(self, path: str) -> None:
        if not os.path.isdir(path):
            raise Exception(
                "{path} should be an existing directory".format(path=path)
            )
        if self._priv_key_filename not in os.listdir(path):
            raise EmptyDirException(
                "{key} file not found in {path}".format(
                    key=self._priv_key_filename, path=path
                )
            )
        with open(os.path.join(path, self._priv_key_filename), "rb") as f:
            self.set_private_key_from_file(f)

    def write_hidden_service(
        self, path: str = None, force: bool = False
    ) -> None:
        path = path or self._hidden_service_path
        if not path:
            raise Exception("Missing hidden service path")
        if not os.path.exists(path):
            raise Exception(
                "{path} should be an existing directory".format(path=path)
            )
        if (
            os.path.exists(os.path.join(path, self._host_filename))
            or os.path.exists(os.path.join(path, self._priv_key_filename))
        ) and not force:
            raise NonEmptyDirException(
                "Use force=True for non empty hidden service directory"
            )
        with open(os.path.join(path, self._priv_key_filename), "wb") as f:
            f.write(self._get_private_key_has_native())
        with open(os.path.join(path, self._host_filename), "w") as f:
            f.write(self.onion_hostname)

    def get_available_private_key_formats(self) -> list:
        "Get private key export availables formats"
        r = re.compile(r"_get_private_key_has_([a-z]+)")
        formats = []
        for method in dir(self):
            m = r.match(method)
            if m:
                formats.append(m[1])
        return formats

    def get_private_key(self, format: str = "native"):
        "Get the private key as specified format"
        method = "_get_private_key_has_{format}".format(format=format)
        if not hasattr(self, method) and not callable(getattr(self, method)):
            raise NotImplementedError("Method {method} if not implemented")
        return getattr(self, method)()

    @abstractmethod
    def _get_private_key_has_native(self) -> bytes:
        "Get private key like in tor native format"
        ...

    @abstractmethod
    def get_public_key(self) -> bytes:
        "Compute public key"
        if not self._priv:
            raise Exception("No private key has been set")

    @abstractmethod
    def get_onion_str(self) -> str:
        "Compute onion address string"
        ...

    @property
    def onion_hostname(self) -> str:
        return "{onion}.onion".format(onion=self.get_onion_str())

    @property
    def version(self) -> str:
        return str(self._version)


class OnionV2(Onion):
    """
    Tor onion address v2 implement
    """

    _priv_key_filename = "private_key"
    _host_filename = "hostname"

    _version = 2

    def gen_new_private_key(self) -> None:
        "Generate new 1024 bits RSA key for hidden service"
        self._save_keypair(RSA.generate(bits=1024))

    def _save_keypair(self, key: RSA.RsaKey) -> None:
        self._priv = key.exportKey("PEM")
        self._pub = key.publickey().exportKey("DER")

    def set_private_key(self, key: bytes) -> None:
        "Add private key"
        if not key.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
            raise Exception(
                "Private key does not seems to be a valid RSA PEM key"
            )
        self._save_keypair(RSA.importKey(key.strip()))

    def _get_private_key_has_native(self) -> bytes:
        "Get RSA private key like in PEM"
        return self._get_private_key_has_pem()

    def _get_private_key_has_pem(self) -> bytes:
        "Get RSA private key like in PEM"
        return RSA.importKey(self._priv).exportKey("PEM")

    def get_public_key(self) -> bytes:
        "Compute public key"
        super().get_public_key()
        return self._pub

    def get_onion_str(self) -> str:
        "Compute onion address string"
        return b32encode(sha1(self._pub[22:]).digest()[:10]).decode().lower()

    def serialize(self):
        return {
            self._host_filename: self.onion_hostname,
            self._priv_key_filename: self.get_private_key().decode(),
        }


class OnionV3(Onion):
    """
    Tor onion address v3 implement
    """

    _header_priv = b"== ed25519v1-secret: type0 ==\x00\x00\x00"
    _header_pub = b"== ed25519v1-public: type0 ==\x00\x00\x00"

    _priv_key_filename = "hs_ed25519_secret_key"
    _pub_key_filename = "hs_ed25519_public_key"
    _host_filename = "hostname"

    _version = 3

    def _save_keypair(self, key: bytes) -> None:
        self._priv = key
        self._pub = Ed25519().public_key_from_hash(key)

    def gen_new_private_key(self) -> None:
        "Generate new tor ed25519 512 bits key"
        random = get_random_bytes(32)
        key = bytearray(sha512(random).digest())
        key[0] &= 248
        key[31] &= 63
        key[31] |= 64
        self._save_keypair(bytes(key))

    def set_private_key(self, key: bytes) -> None:
        "Add private key"
        if not key.startswith(self._header_priv):
            raise Exception(
                "Private key does not seems to be a valid ed25519 tor key"
            )
        parsed_key = key[32:]
        if len(parsed_key) != 64:
            raise Exception(
                "Private key does not seem to have the good lenght"
            )
        self._save_keypair(parsed_key)

    def set_private_key_from_file(self, file: BinaryIO):
        "Load private key from file"
        self.set_private_key(file.read())

    def _get_private_key_has_native(self) -> bytes:
        "Get RSA private key like in PEM"
        return self._header_priv + self._priv

    def get_public_key(self) -> bytes:
        "Compute public key"
        super().get_public_key()
        return self._header_pub + self._pub

    def write_hidden_service(
        self, path: str = None, force: bool = False
    ) -> None:
        path = path or self._hidden_service_path
        super().write_hidden_service(path, force)
        with open(os.path.join(path, self._pub_key_filename), "wb") as f:
            f.write(self.get_public_key())

    def get_onion_str(self) -> str:
        "Compute onion address string"
        version_byte = b"\x03"

        def checksum(pubkey):
            checksum_str = ".onion checksum".encode("ascii")
            return sha3_256(checksum_str + self._pub + version_byte).digest()[
                :2
            ]

        return (
            b32encode(self._pub + checksum(self._pub) + version_byte)
            .decode()
            .lower()
        )

    def serialize(self):
        return {
            self._host_filename: self.onion_hostname,
            self._priv_key_filename: b64encode(
                self.get_private_key()
            ).decode(),
            self._pub_key_filename: b64encode(self.get_public_key()).decode(),
        }
