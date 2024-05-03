from conftest import sign_certificate
import tempfile
import pytest
import ctadata


@pytest.mark.timeout(30)
def test_apiclient_upload_certificate(testing_certificate_service):
    ctadata.APIClient.certificateservice = testing_certificate_service['url']

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = f"{tmpdir}/cert-file"
        certificate = sign_certificate(testing_certificate_service['ca'], 1)
        open(cert_file, 'w').write(certificate)
        cert_key = "cta"
        res = ctadata.upload_personal_certificate(cert_file, cert_key)
        assert (
            type(res) is dict
            and res['message'] is not None
            and res['validity'] is not None
        )


@pytest.mark.timeout(30)
def test_apiclient_upload_admin_cert(testing_certificate_service):
    ctadata.APIClient.certificateservice = testing_certificate_service['url']

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = f"{tmpdir}/cert-file"
        certificate = sign_certificate(testing_certificate_service['ca'], 1)
        open(cert_file, 'w').write(certificate)
        res = ctadata.upload_shared_certificate(
            certificate_file_path=cert_file
        )
    assert (
        type(res) is dict
        and res['message'] is not None
        and res['certificateUploaded'] is True
    )
