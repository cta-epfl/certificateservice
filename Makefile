
listen:
	FLASK_SECRET=$(shell cat secret-env.sh) \
	CTACS_CLIENTCERT=/tmp/x509up_u1000 \
	CTACS_CABUNDLE=/home/savchenk/cabundle.pem \
	FLASK_APP=certificateservice \
		     flask run --debug

secret-env.sh:
	openssl rand -hex 64 > secret-env.sh
	chmod 700 secret-env.sh
