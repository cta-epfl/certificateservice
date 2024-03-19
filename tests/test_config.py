from conftest import ca_certificate, sign_certificate
from flask import url_for
import io
import pytest
from typing import Any


@pytest.mark.timeout(30)
def test_upload_cert_form(app: Any, client: Any):
    certificate = sign_certificate(app.ca, 1)
    data = {'certificate': (
        io.BytesIO(bytes(certificate, encoding='UTF-8')), 'certificate.pem'
    )}

    client.post(
        url_for('personnal_certificate_form'),
        data=data,
        buffered=True,
        content_type="multipart/form-data",
    )

    r = client.get(url_for('get_certificate'))
    assert r.status_code == 200 and \
        r.json['certificate'] == certificate and \
        r.json['cabundle'] == open(app.config['CTACS_CABUNDLE'], 'r').read()


@pytest.mark.timeout(30)
def test_valid_owncert_config(app: Any, client: Any):
    certificate = sign_certificate(app.ca, 1)
    r = client.post(url_for('upload_certificate'), json={
        'certificate': certificate})
    assert r.status_code == 200


@pytest.mark.timeout(30)
def test_invalid_owncert_config(app: Any, client: Any):
    with ca_certificate() as alt_ca:
        certificate = sign_certificate(alt_ca, 1)
        r = client.post(url_for('upload_certificate'), json={
            'certificate': certificate})
        assert r.status_code == 400 and \
            r.text == 'invalid certificate verification chain'


@pytest.mark.timeout(30)
def test_expired_owncert_config(app: Any, client: Any):
    certificate = sign_certificate(app.ca, -1)
    r = client.post(url_for('upload_certificate'), json={
                    'certificate': certificate})
    assert r.status_code == 400 and \
        r.text == 'invalid certificate verification chain'


@pytest.mark.timeout(30)
def test_fake_owncert_config(app: Any, client: Any):
    certificate = 'fake certificate string'
    r = client.post(url_for('upload_certificate'), json={
        'certificate': certificate})
    assert r.status_code == 400 and \
        r.text.startswith('no valid certificate provided')


@pytest.mark.timeout(30)
def test_invalid_chain_maincert_config(app: Any, client: Any):
    with ca_certificate() as alt_ca:
        certificate = sign_certificate(alt_ca, 1)
        r = client.post(
            url_for('upload_main_certificate'),
            json={
                'certificate': certificate,
            }
        )
        assert r.status_code == 400 and \
            r.text == 'invalid certificate verification chain'


@pytest.mark.timeout(30)
def test_new_cert_maincert_config(app: Any, client: Any):
    certificate = sign_certificate(app.ca, 1)
    r = client.post(
        url_for('upload_main_certificate'),
        json={'certificate': certificate}
    )
    assert r.status_code == 200


@pytest.mark.timeout(30)
def test_get_cert_config(app: Any, client: Any):
    certificate = sign_certificate(app.ca, 1)
    r = client.post(
        url_for('upload_certificate'),
        json={'certificate': certificate}
    )
    r = client.get(url_for('get_certificate'))
    assert r.status_code == 200 and \
        r.json['certificate'] == certificate and \
        r.json['cabundle'] == open(app.config['CTACS_CABUNDLE'], 'r').read()


@pytest.mark.timeout(30)
def test_get_cert_main_config(app: Any, client: Any):
    r = client.get(url_for('get_certificate'))
    assert r.status_code == 200 and \
        r.json['certificate'] == \
        open(app.config['CTACS_CLIENTCERT'], 'r').read() and \
        r.json['cabundle'] == open(app.config['CTACS_CABUNDLE'], 'r').read()


@pytest.mark.timeout(30)
def test_original_maincert_config(app: Any, client: Any):
    certificate = sign_certificate(app.ca, 365)
    r = client.post(
        url_for('upload_main_certificate'),
        json={
            'certificate': certificate,
        }
    )
    assert r.status_code == 400 and r.text == \
        'certificate validity too long, please generate a ' +\
        'short-lived (max 7 day) proxy certificate for uploading. ' +\
        'Please see https://ctaodc.ch/ for more details.'
