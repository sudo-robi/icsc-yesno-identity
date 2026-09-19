"""WSGI prefix strip: lets one Flask app serve at root (Render/offline/gunicorn)
AND under a Vercel services subpath (/issuer/*, /verifier/*) with zero duplication.
agency: backend-architect | ECC: backend-patterns middleware pattern.
"""


class PrefixStrip:
    def __init__(self, wsgi_app, prefixes):
        self.wsgi = wsgi_app
        self.prefixes = tuple(prefixes)

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        for p in self.prefixes:
            if path == p or path.startswith(p + "/"):
                environ["PATH_INFO"] = path[len(p):] or "/"
                environ["SCRIPT_NAME"] = environ.get("SCRIPT_NAME", "") + p
                break
        return self.wsgi(environ, start_response)
