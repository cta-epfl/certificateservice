import logging

from certificateservice.app import app


def main():
    logging.basicConfig(level=logging.DEBUG)
    app.run(host='0.0.0.0', port=5001)


if __name__ == "__main__":
    main()
