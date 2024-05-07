from datetime import datetime, timedelta
import copy
import hashlib
import os
import psutil
import pytest
import re
import signal
import subprocess
import tempfile
import time
from threading import Thread

from contextlib import contextmanager

__this_dir__ = os.path.join(os.path.abspath(os.path.dirname(__file__)))


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


@pytest.fixture(scope="function")
def app():
    with tempfile.TemporaryDirectory() as tmpdir:
        from certificateservice.app import app

        with ca_certificate() as ca:
            certificate = sign_certificate(ca, 1)

            client_cert_file = f'{tmpdir}/clientcert.crt'
            open(client_cert_file, 'w').write(certificate)

            app.config.update({
                "TESTING": True,
                "CTACS_DISABLE_ALL_AUTH": True,
                "CTACS_MAIN_CERT_ALLOWED_USER": 'anonymous',
                "DEBUG": True,
                "CTACS_CABUNDLE": ca['crt_file'],
                "CTACS_CLIENTCERT": client_cert_file,
                "CTACS_CERTIFICATE_DIR": tmpdir,
                "SERVER_NAME": 'app',
            })

            app.ca = ca

            yield app


def kill_child_processes(parent_pid, sig=signal.SIGINT):
    try:
        parent = psutil.Process(parent_pid)
        children = parent.children(recursive=True)
        for process in children:
            process.send_signal(sig)
    except psutil.NoSuchProcess:
        return


@pytest.fixture(scope="session")
def testing_certificate_service(pytestconfig):
    with tempfile.TemporaryDirectory() as tmpdir:

        with ca_certificate() as ca:
            certificate = sign_certificate(ca, 1)

            client_cert_file = f'{tmpdir}/clientcert.crt'
            open(client_cert_file, 'w').write(certificate)

            rootdir = pytestconfig.rootdir

            env = copy.deepcopy(dict(os.environ))
            print(("rootdir", str(rootdir)))
            env['PYTHONPATH'] = str(rootdir)+":"+str(rootdir)+"/tests:" + \
                str(rootdir)+'/bin:' + \
                __this_dir__+":"+os.path.join(__this_dir__, "../bin:") + \
                env.get('PYTHONPATH', "")

            env['CTACS_DISABLE_ALL_AUTH'] = 'True'
            env['CTACS_MAIN_CERT_ALLOWED_USER'] = 'anonymous'
            env["CTACS_CABUNDLE"] = ca['crt_file']
            env["CTACS_CLIENTCERT"] = client_cert_file
            env['CTACS_CERTIFICATE_DIR'] = tmpdir

            print(("pythonpath", env['PYTHONPATH']))

            cmd = ["python", "certificateservice/cli.py"]

            print(f"\033[33mcommand: {cmd}\033[0m")

            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                env=env,
            )

            url_store = [None]

            def follow_output():
                url_store[0] = None
                for line in iter(p.stdout):
                    line = line.decode()

                    NC = '\033[0m'
                    if 'ERROR' in line:
                        C = '\033[31m'
                    else:
                        C = '\033[34m'

                    print(f"{C}following server: {line.rstrip()}{NC}")
                    m = re.search(r"INFO:waitress:Serving on (.*?:5001)", line)
                    if m:
                        # alternatively get from configenv
                        url_store[0] = m.group(1).strip()
                        print(f"{C}following server: found url:{url_store[0]}")

                    if re.search(r"\* Debugger PIN:.*?", line):
                        url_store[0] = url_store[0].replace(
                            "0.0.0.0", "127.0.0.1")
                        print(
                            f"{C}following server: ready, url {url_store[0]}")

            thread = Thread(target=follow_output, args=())
            thread.start()

            started_waiting = time.time()
            while url_store[0] is None:
                print("waiting for server to start since",
                      time.time() - started_waiting)
                time.sleep(0.2)
            time.sleep(0.5)

            service = url_store[0]

            yield dict(
                url=service,
                pid=p.pid,
                ca=ca,
            )

            kill_child_processes(p.pid, signal.SIGINT)
            os.kill(p.pid, signal.SIGINT)
