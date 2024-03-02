import datetime
from datetime import timedelta
import uuid
import tempfile
import hashlib
import requests
import subprocess
import json
from subprocess import Popen, PIPE, DEVNULL

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# https://freeoid.pythonanywhere.com/
EXTENSION_ID_BY_NAME = {
    "UrkelProof": "1.3.6.1.4.1.54392.5.1620",
    "DnssecChain": "1.3.6.1.4.1.54392.5.1621",
}


class DaneBackend(object):
    def __init__(self, config):
        self.config = config
        self.send_emails = config["sendgrid"].get(
            "send_emails", "false") == "true"

    def sign(self, csr, subjectDN, subjectAltNames, email):
        print("New request:", subjectDN, subjectAltNames, email)

        # Load CSR
        csr_obj = x509.load_der_x509_csr(csr, backend=default_backend())

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subjectDN),
        ])

        # Generate temporary CA
        print("Generating ephemeral CA...")
        ca_cert, ca_privkey = self.generate_ephemeral_ca()

        # Build certificate
        print("Building certificate...")
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            csr_obj.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in subjectAltNames]),
            critical=False,
        )

        # Experimental HIP-0017 Certificate (Stateless DANE)
        if email and "+nohip17" not in email:
            try:
                print("Attempting to fetch HIP-17 extensions...")
                hip17_exts = self.get_hip17_extensions(subjectDN)
                for ext in hip17_exts:
                    certificate = certificate.add_extension(ext, False)
                # shorter certificates
                certificate = certificate.not_valid_before(
                    datetime.datetime.utcnow() - timedelta(days=1)
                ).not_valid_after(
                    datetime.datetime.utcnow() + timedelta(days=2)
                )
                print("Successfully added HIP-17 extensions!")
            except Exception as e:
                print("Error fetching HIP-17 extensions:")
                print(e)
                # Only error if HIP-17 was explicitly requested
                # Otherwise ignore silently and continue with non-HIP-17 cert
                if "+hip17" in email:
                    raise e
                else:
                    print("Silently ignoring HIP-17 error.")
        else:
            if email:
                print("Skipping HIP-17, was explicitly requested.")

        # Set dates if not HIP-17
        if certificate._not_valid_before is None:
            if email and '+longttl' in email:
                certificate = certificate.not_valid_before(
                        datetime.datetime.utcnow() - timedelta(days=1)
                    ).not_valid_after(
                        datetime.datetime.utcnow() + timedelta(days=365)
                    )
            else:
                certificate = certificate.not_valid_before(
                        datetime.datetime.utcnow() - timedelta(days=1)
                    ).not_valid_after(
                        datetime.datetime.utcnow() + timedelta(days=2)
                    )

        # Sign certificate with CA"s key
        print("Signing certificate...")
        certificate = certificate.sign(
            ca_privkey, hashes.SHA256(), backend=default_backend())

        # Bundle domain and CA certificate into  fullchain (PKCS#7, DER)
        print("Bundling certificates...")
        bundle = self.create_fullchain([
            certificate.public_bytes(Encoding.PEM),
            ca_cert.public_bytes(Encoding.PEM)
        ])

        if email and "+email" in email and self.send_emails:
            # TLSA
            cert_bytes = certificate.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            tlsa_digest = hashlib.sha256(cert_bytes).hexdigest()
            print("TLSA:", f"_443._tcp.{subjectDN}. TLSA 3 1 1 {tlsa_digest}")

            # Send email
            try:
                self.send_cert_issue_email(email, subjectDN, tlsa_digest)
                pass
            except Exception as e:
                print(e)

        print("Done!")
        return (bundle, None)

    def generate_ephemeral_ca(self):

        # Generate CA"s key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,
                               u"Handshake Tools Ephemeral CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                               u"Handshake Tools"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                               u"ACME"),
        ])

        # Build CA certificate
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).not_valid_before(
            datetime.datetime.utcnow() - timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.utcnow() + timedelta(days=365)
        ).serial_number(
            int(uuid.uuid4())
        ).public_key(
            public_key
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        # Sign CA certificate with CA key
        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        return certificate, private_key

    def create_fullchain(self, certs):
        # OpenSSL only reads certificates only from files and not stdin,
        # so we write them to NamedTemporaryFiles which are deleted on close
        files = []
        certfile_args = []
        for cert in certs:
            f = tempfile.NamedTemporaryFile()
            f.write(cert)
            f.flush()
            certfile_args += ["-certfile", f.name]
            files.append(f)

        proc = Popen(
            ["openssl", "crl2pkcs7", "-nocrl", "-outform", "DER"] + certfile_args,
            stdin=PIPE,
            stdout=PIPE,
            stderr=DEVNULL,
        )
        pem_cert = proc.stdout.read()

        for file in files:
            file.close()

        return pem_cert

    def send_cert_issue_email(self, email, domain, digest):
        headers = {
            "Authorization": f"Bearer {self.config['sendgrid']['api_key']}",
            "Content-Type": "application/json"
        }

        payload = {
            "template_id": self.config["sendgrid"]["template_id"],
            "personalizations": [{
                "dynamic_template_data": {
                    "domain": domain,
                    "digest": digest
                },
                "to": [{"email": email}]
            }],
            "from": {
                "name": self.config["sendgrid"]["from_name"],
                "email": self.config["sendgrid"]["from_email"]
            },
            "asm": {
                "group_id": int(self.config["sendgrid"]["asm_group_id"])
            }
        }
        r = requests.post("https://api.sendgrid.com/v3/mail/send",
                          headers=headers, json=payload)

        if r.status_code not in [200, 202]:
            print(r.status_code)
            print(r.text)

    def get_hip17_extensions(self, name: str):
        proc = subprocess.run(
            ["stateless-dane", "get-ext-data", name, "--parsed", "false"], capture_output=True, text=True)

        if proc.stderr:
            print(proc.stderr)
            raise Exception(
                'Error when building HIP-17 certificate. Check log for more details.')

        data = json.loads(proc.stdout)
        # print(data)

        extensions = []

        for el in data:
            ext_id_value = EXTENSION_ID_BY_NAME.get(el["extnID"])
            extensions.append(
                x509.UnrecognizedExtension(
                    oid=x509.ObjectIdentifier(ext_id_value),
                    value=bytes.fromhex(el["extnValue"])
                )
            )

        # print(extensions)
        return extensions
