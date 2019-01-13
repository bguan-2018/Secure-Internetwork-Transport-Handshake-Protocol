import random, secrets, hashlib, pem, datetime, os.path, traceback
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.backends import default_backend

crl_key_file_path  = "crl_key.pem"
imdt_key_file_path = "intermediate_key.pem"
sith_key_file_path = "sith_key.pem"

root_cert_file_path = "20184_root_signed.cert"
imdt_cert_file_path = "signed_intermediate_certificate.cert"
sith_cert_file_path = "sith_certificate.cert"
rvct_cert_file_path = "revocation_list.cert"
cert_file_path_list = [root_cert_file_path, imdt_cert_file_path, sith_cert_file_path]

def gen_sith_cert():
    signing_key = load_private_key_file(imdt_key_file_path)
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    with open(sith_key_file_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.BestAvailableEncryption(b",B]XA==H78Rq{b!x"),
        ))
    issuer = None
    with open(imdt_cert_file_path, 'rb') as imdt_cert_file:
        imdt_cert = x509.load_pem_x509_certificate(imdt_cert_file.read(), default_backend())
        issuer = imdt_cert.subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Maryland"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Baltimore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Johns Hopkins University"),
        x509.NameAttribute(NameOID.COMMON_NAME, gen_common_name(issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        # Should we use UTC time?
        datetime.datetime.now()
    ).not_valid_after(
        datetime.datetime.now() + datetime.timedelta(days=1)
    ).sign(signing_key, hashes.SHA256(), default_backend())

    with open(sith_cert_file_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def gen_common_name(issuer_commmon_name):
    max_address = 2**16-1
    a = random.randint(0, max_address)
    b = random.randint(0, max_address)
    c = random.randint(0, max_address)
    subject = issuer_commmon_name + str(a) + "." + str(b) + "." + str(c)
    return subject

def load_private_key_file(key_file_path):
    with open(key_file_path, 'rb') as key_file:
        private_key = load_private_key_string(key_file.read())
    return private_key

def load_private_key_string(key_string):
    return serialization.load_pem_private_key(key_string, password=None, backend=default_backend())

def load_certicate_chain():
    cert_list = []
    try:
        if not os.path.isfile(sith_cert_file_path):
            gen_sith_cert()
        else:
            sith_cert = x509.load_pem_x509_certificate(open(sith_cert_file_path, 'rb').read(), default_backend())
            if not verify_cert_datetime_validity(sith_cert):
                gen_sith_cert()
        for path in cert_file_path_list:
            with open(path, 'rb') as cert_file:
                cert_list.append(cert_file.read())
    except Exception as e:
        print("Failed to load certificates! ")
        traceback.print_exc()
    return cert_list

def verify_certificate_chain(cert_chain_data_list):
    if len(cert_chain_data_list) == 0:
        return False

    cert_list = []
    for bytes in cert_chain_data_list:
        cert = x509.load_pem_x509_certificate(bytes, default_backend())
        cert_list.append(cert)
    parent_cert = None
    is_signed_by_CA = False
    # Checking signatures
    for cert in cert_list:
        print(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
        # Check if in CRL
        if exists_in_revocation_list(cert):
            print("Certificate is revoked.")
            return False
        # Check if the certificate came from a CA
        if verify_root_ca_cert(cert):
            is_signed_by_CA = True
        # Check if the certificate is valid
        if not verify_cert_datetime_validity(cert):
            return False
        # Check if the signature is signed by the parent
        if parent_cert == None:
            parent_cert = cert
        try:
            parent_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm)
            )
        except InvalidSignature as e:
            print("signature: " + str(cert.signature))
            print("bytes: " + str(cert.tbs_certificate_bytes))
            print("hash: " + str(cert.signature_hash_algorithm))
            return False
        # Checks if subject is issuer
        if not verify_subject_issuer(parent_cert.subject, cert.issuer):
            return False
        parent_cert = cert
    if is_signed_by_CA:
        return True
    else:
        return False

def verify_cert_datetime_validity(cert):
    today = datetime.datetime.now()
    if cert.not_valid_after < today or cert.not_valid_before > today:
        return False
    else:
        return True

def verify_subject_issuer(parent_subject, issuer):
    return (parent_subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            == issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)

def verify_root_ca_cert(cert):
    with open(root_cert_file_path, 'rb') as root_cert_file:
        root_cert = x509.load_pem_x509_certificate(root_cert_file.read(), default_backend())
        if root_cert.tbs_certificate_bytes == cert.tbs_certificate_bytes and root_cert.signature == cert.signature:
            return True
    return False

def exists_in_revocation_list(cert):
    if not os.path.isfile(rvct_cert_file_path):
        return False
    try:
        with open(rvct_cert_file_path, 'rb') as crl_file:
            crl = x509.load_pem_x509_crl(crl_file.read(), default_backend())
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
                return True
    except Exception as e:
      traceback.print_exc()
    return False

def gen_crl():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    with open(crl_key_file_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"9MgEBdd#=/f+D`9a"),
        ))

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io CA'),
    ]))
    one_day = datetime.timedelta(1, 0, 0)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + one_day)
    revoked_cert = x509.RevokedCertificateBuilder().serial_number(
        89894
    ).revocation_date(
        datetime.datetime.today()
    ).build(default_backend())
    builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(
        private_key = private_key,
        algorithm = hashes.SHA256(),
        backend = default_backend()
    )
    with open(rvct_cert_file_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))


if __name__ ==  "__main__":
    # gen_crl()
    print(str(verify_certificate_chain(load_certicate_chain())))
