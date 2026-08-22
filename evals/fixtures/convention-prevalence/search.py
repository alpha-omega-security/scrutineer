import flask

from store import query

app = flask.Flask(__name__)


@app.get("/search")
def search():
    term = flask.request.args.get("q", "")
    return flask.jsonify(query("SELECT id FROM items WHERE name = '%s'" % term))
