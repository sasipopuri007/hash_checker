"""
Entry point alias for web_app.py.
Allows running the web dashboard via 'python app.py' as well as 'python web_app.py'.
"""

from web_app import app

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Secure Network File Transfer Web Application")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    args = parser.parse_args()

    print(f"\n==================================================================")
    print(f" Web Dashboard running at: http://{args.host}:{args.port}")
    print(f" Press Ctrl+C to stop.")
    print(f"==================================================================\n")
    app.run(host=args.host, port=args.port, debug=args.debug)
