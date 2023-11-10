from conftest import ca_certificate, sign_certificate
import tempfile
import pytest
import ctadata


@pytest.mark.timeout(30)
def test_apiclient_upload_certificate(testing_certificate_service):
    ctadata.APIClient.downloadservice = testing_certificate_service['url']

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = f"{tmpdir}/cert-file"
        certificate = sign_certificate(testing_certificate_service['ca'], 1)
        open(cert_file, 'w').write(certificate)
        res = ctadata.upload_personal_certificate(cert_file)
        assert (
            type(res) is dict
            and res['message'] is not None
            and res['validity'] is not None
        )


@pytest.mark.timeout(30)
def test_apiclient_upload_admin_cert(testing_certificate_service):
    ctadata.APIClient.downloadservice = testing_certificate_service['url']

    with ca_certificate() as alt_ca:
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_file = f"{tmpdir}/cert-file"
            certificate = sign_certificate(alt_ca, 1)
            open(cert_file, 'w').write(certificate)
            res = ctadata.upload_shared_certificate(
                certificate_file=cert_file,
                cabundle_file=alt_ca['crt_file'],
            )
        assert (
            type(res) is dict
            and res['message'] is not None
            and res['cabundleUploaded'] is True
            and res['certificateUploaded'] is True
        )
