class PushClient:
    def __init__(self, api_key, base_url="https://push.example.test"):
        self.api_key = api_key
        self.base_url = base_url

    def _request(self, method, path, body):
        return {
            "method": method,
            "url": self.base_url + path,
            "headers": {"Authorization": "Bearer " + self.api_key},
            "json": body,
        }

    def register(self, platform, device_token):
        if platform not in ("ios", "android"):
            raise ValueError("unknown platform")
        return self._request("POST", "/devices", {"platform": platform, "token": device_token})

    def send(self, device_token, message):
        return self._request("POST", "/send", {"token": device_token, "message": message})

    def unregister(self, device_token):
        return self._request("DELETE", "/devices/" + device_token, None)
