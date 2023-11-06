from datetime import datetime, timedelta
import hashlib
import os
import pytest
import tempfile
from threading import Thread

from contextlib import contextmanager


def hash_file(filename):
    """"Returns the SHA-1 hash of the file provided"""
    h = hashlib.sha1()

    with open(filename, 'rb') as file:
        while (chunk := file.read(1024**2)) != b'':
            h.update(chunk)

    return h.hexdigest()


def generate_random_file(filename, size):
    with open(filename, 'wb') as fout:
        fout.write(os.urandom(size))


@contextmanager
def ca_certificate():
    with tempfile.TemporaryDirectory() as tmpdir:
        # RootCA key
        ca_key_file = tmpdir+'/rootCA.key'
        os.system('openssl genrsa -out ' + ca_key_file + ' 4096')

        # RootCA Certificate
        ca_crt_file = tmpdir+'/rootCA.crt'
        os.system('openssl req -x509 -new -batch -nodes -key '+ca_key_file +
                  ' -sha256 -days 365 -out ' + ca_crt_file +
                  ' -subj "/C=CH/ST=Lausanne/L=Lausanne/O=EPFL' +
                  '/OU=LASTRO/CN=lastro.epfl.ch"')

        yield {'key_file': ca_key_file, 'crt_file': ca_crt_file}


def sign_certificate(ca, duration):
    with tempfile.TemporaryDirectory() as tmpdir:
        # User key
        key_file = tmpdir+'/user.key'
        os.system('openssl genrsa -out ' + key_file + ' 4096')
        # Cert signing request
        csr_file = tmpdir+'/request.csr'
        os.system('openssl req -new -batch -key ' + key_file +
                  ' -out ' + csr_file)

        if duration < 0:
            date = (datetime.today()+timedelta(days=duration-1))\
                .strftime("%Y-%m-%d %H:%M:%S")
            certificate = os.popen('faketime "' + str(date) + '"' +
                                   ' openssl x509 -req' +
                                   ' -in ' + csr_file +
                                   ' -CAkey ' + ca['key_file'] +
                                   ' -CA ' + ca['crt_file'] +
                                   ' -CAcreateserial' +
                                   ' -days 1').read()
        else:
            certificate = os.popen('openssl x509 -req' +
                                   ' -in ' + csr_file +
                                   ' -CAkey ' + ca['key_file'] +
                                   ' -CA ' + ca['crt_file'] +
                                   ' -CAcreateserial' +
                                   ' -days '+str(duration)).read()

        return certificate


@pytest.fixture(scope="session")
def app():
    with tempfile.TemporaryDirectory() as tmpdir:
        from certificateservice.app import app

        with ca_certificate() as ca:
            certificate = sign_certificate(ca, 1)

            client_cert_file = f'{tmpdir}/clientcert.crt'
            open(client_cert_file, 'w').write(certificate)

            app.config.update({
                "TESTING": True,
                "CTADS_DISABLE_ALL_AUTH": True,
                "DEBUG": True,
                "CTADS_CABUNDLE": ca['crt_file'],
                "CTADS_CLIENTCERT": client_cert_file,
                "CTADS_CLIENTCERT_DIR": tmpdir,
                "SERVER_NAME": 'app',
            })

            app.ca = ca

            yield app

