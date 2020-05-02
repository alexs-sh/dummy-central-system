use std::fs::{create_dir_all, File};
use std::io::prelude::*;
use std::process::Command;
use std::string::String;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(PartialEq)]
pub enum Format {
    DER,
    PEM,
}

pub trait CertificationAuthority {
    fn sign(&self, csr: CertificateSignRequest) -> Result<Vec<Certificate>, &str>;
}

pub struct Certificate {
    pub data: Vec<u8>,
    pub format: Format,
}

pub struct CertificateSignRequest {
    pub data: Vec<u8>,
    pub format: Format,
}

pub struct DefaultCertificationAuthoritySettings {
    pub directory: String,
    pub new: bool,
}

pub struct DefaultCertificationAuthority {
    settings: DefaultCertificationAuthoritySettings,
    certificates: Vec<CertificateKeyPair>,
}

struct CertificateKeyPair {
    key: String,
    certificate: String,
}

impl CertificateKeyPair {
    fn get_key(&self) -> &str {
        self.key.as_str()
    }
    fn get_certificate(&self) -> &str {
        self.certificate.as_str()
    }
}

impl DefaultCertificationAuthority {
    pub fn new(settings: DefaultCertificationAuthoritySettings) -> DefaultCertificationAuthority {
        DefaultCertificationAuthority {
            settings,
            certificates: Vec::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), &str> {
        if !self.settings.new {
            return Ok(());
        }

        let key_name = "root-key.pem";
        let cert_name = "root-cert.pem";
        let cn = "DefaultCertificationAuthority";

        let pair = CertificateKeyPair {
            key: self.get_workdir().to_string() + key_name,
            certificate: self.get_workdir().to_string() + cert_name,
        };

        let _ = create_dir_all(self.get_workdir());

        if !self.generate_key(pair.get_key()) {
            return Err("can't generate key");
        }

        if !self.generate_certificate(pair.get_certificate(), cn, pair.get_key()) {
            return Err("can't generate certificate");
        }

        println!("{}", self.read_key(pair.get_key()));
        println!("{}", self.read_certificate(pair.get_certificate()));

        self.certificates.push(pair);

        Ok(())
    }

    pub fn get_workdir(&self) -> &str {
        self.settings.directory.as_str()
    }

    pub fn read_key(&self, file: &str) -> String {
        /* openssl ec -in ca/root-key.pem -text*/
        if let Ok(out) = Command::new("openssl")
            .args(&["ec", "-text", "-in", file])
            .output()
        {
            std::str::from_utf8(out.stdout.as_slice())
                .unwrap()
                .to_string()
        } else {
            String::new()
        }
    }

    pub fn read_certificate(&self, file: &str) -> String {
        /* ✗ openssl x509 -in /tmp/rust-cs/ca/root-cert.pem -text*/
        if let Ok(out) = Command::new("openssl")
            .args(&["x509", "-text", "-in", file])
            .output()
        {
            std::str::from_utf8(out.stdout.as_slice())
                .unwrap()
                .to_string()
        } else {
            String::new()
        }
    }

    fn generate_key(&self, out: &str) -> bool {
        /* openssl ecparam -name prime256v1 -genkey -noout -out test-key-root.pem*/
        let res = Command::new("openssl")
            .args(&[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                out,
            ])
            .spawn()
            .unwrap()
            .wait();
        self.sync();
        res.is_ok()
    }

    fn generate_certificate(&self, out: &str, cn: &str, key: &str) -> bool {
        /* openssl req -x509 -new -key rootCA.key -days 365 -out rootCA.crt -subj "/CN=John Doe /C=US" */
        let mut subject = "/CN=".to_string() + cn;
        subject += "/C=US";

        let res = Command::new("openssl")
            .args(&[
                "req",
                "-x509",
                "-new",
                "-key",
                key,
                "-days",
                "365",
                "-out",
                out,
                "-subj",
                subject.as_str(),
            ])
            .spawn()
            .unwrap()
            .wait();
        self.sync();
        res.is_ok()
    }

    fn sign_certificate_request(&self, csr: &str, pair: &CertificateKeyPair, out: &str) -> bool {
        /*openssl x509 -req -in csr.pem -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out out.crt -days 100*/
        let res = Command::new("openssl")
            .args(&[
                "x509",
                "-req",
                "-in",
                csr,
                "-CA",
                pair.get_certificate(),
                "-CAkey",
                pair.get_key(),
                "-CAcreateserial",
                "-days",
                "100",
                "-out",
                out,
                "-outform",
                "DER",
            ])
            .spawn()
            .unwrap()
            .wait();
        self.sync();
        res.is_ok()
    }

    fn sync(&self) {
        let mut c = Command::new("sync").spawn().unwrap();
        let _ = c.wait();
    }
}

impl CertificationAuthority for DefaultCertificationAuthority {
    fn sign(&self, csr: CertificateSignRequest) -> Result<Vec<Certificate>, &str> {
        if csr.format != Format::PEM {
            return Err("unsupported format");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let csr_name = self.get_workdir().to_string() + "csr" + now.to_string().as_str();
        let cert_name = self.get_workdir().to_string() + "cert" + now.to_string().as_str();

        let mut csr_file = File::create(csr_name.as_str()).unwrap();
        let _ = csr_file.write(csr.data.as_slice());

        if self.sign_certificate_request(
            csr_name.as_str(),
            &self.certificates[0],
            cert_name.as_str(),
        ) {
            let mut cert_file = File::open(cert_name.as_str()).unwrap();
            let mut input = Vec::<u8>::new();

            if cert_file.read_to_end(&mut input).is_ok() {
                let cert = Certificate {
                    format: Format::PEM,
                    data: input,
                };
                Ok(vec![cert])
            } else {
                Err("failed to read certificate")
            }
        } else {
            Err("failed to sign")
        }
    }
}
