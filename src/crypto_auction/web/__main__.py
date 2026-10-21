"""Development server: python -m crypto_auction.web"""

from crypto_auction.web import create_app


def main() -> None:
    # Debug mode is opt-in via FLASK_DEBUG=1 (read by app.run) or
    # `flask --app crypto_auction.web run --debug`: the Werkzeug debugger
    # serves an interactive Python console, so it must never be on by default.
    create_app().run(port=5000)


if __name__ == "__main__":
    main()
