import json
import sys

import fire
import yaml

from .onion import NonEmptyDirException
from .onion import OnionV2
from .onion import OnionV3


class Format(object):
    def __init__(self, format: str):
        attr = "print_{format}".format(format=format)
        if not hasattr(self, attr):
            raise Exception("Output format not valid")
        self.method = getattr(self, attr)
        print("FYI: Binary data is base64 encoded", file=sys.stderr)

    def print(self, data: dict):
        self.method(data)

    def print_plain(self, data: dict):
        for key, value in data.items():
            print("{key}:\n{value}".format(key=key, value=value))

    def print_json(self, data: dict):
        print(json.dumps(data, indent=4))

    def print_yaml(self, data: dict):
        print(yaml.dump(data))


class Pytor(object):

    _obj = {
        2: OnionV2,
        3: OnionV3,
    }

    def __init__(self, version: int = 3, format: str = "plain"):
        if version not in self._obj:
            raise Exception("Onion version not valid")
        self._version = version
        self._print = Format(format).print
        self._stderr: lambda x: print(x, file=sys.stderr)

    @property
    def _cls(self):
        return self._obj[self._version]

    def new(self):
        obj = self._cls()
        self._print(obj.serialize())

    def new_hidden_service(self, path: str, force: bool = False):
        obj = self._cls()
        try:
            obj.write_hidden_service(path=path, force=force)
        except NonEmptyDirException:
            s = input(
                "Dir {path} not empty, override? [Y/n]".format(path=path)
            )
            if not s or s.lower() == "y":
                obj.write_hidden_service(path=path, force=True)
            else:
                print("Canceled...")
        self._print({"path": path, **obj.serialize()})


def main():
    fire.Fire(Pytor)


if __name__ == "__main__":
    main()
