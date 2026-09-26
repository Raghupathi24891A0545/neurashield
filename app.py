import os
# Vercel deployment entrypoint
from backend.app import app

# Export the Flask WSGI app directly.
# Vercel Python builder will use the `app` variable as the entrypoint.
if __name__ == "__main__":
    is_debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=is_debug, use_reloader=False, host="127.0.0.1", port=5000, threaded=True)
