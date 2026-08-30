from flask import Flask
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch_url():
    # reachable from an HTTP entrypoint -> uses `requests`
    resp = requests.get("http://example.com")
    return resp.text


def unused_helper():
    # never called from anywhere -> not reachable
    return requests.post("http://example.com/unused")


if __name__ == "__main__":
    app.run()
