import argparse
import hashlib
import json
import urllib.request


def package(path):
    with open(path, "rb") as handle:
        image = handle.read()
    manifest = {"sha256": hashlib.sha256(image).hexdigest(), "size": len(image)}
    return image, manifest


def main():
    parser = argparse.ArgumentParser(description="Package a firmware image and upload it to the release server")
    parser.add_argument("image")
    parser.add_argument("--server", default="http://localhost:8000")
    args = parser.parse_args()
    image, manifest = package(args.image)
    request = urllib.request.Request(args.server + "/upload", data=image, method="POST")
    urllib.request.urlopen(request)
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
