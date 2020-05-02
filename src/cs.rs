use crate::ocpp::{CentralSystem as OcppCentralSystem, Command, Message, MessageType, Status};
use crate::x509::{
    CertificateSignRequest, CertificationAuthority, DefaultCertificationAuthority,
    DefaultCertificationAuthoritySettings, Format,
};
use chrono::{DateTime, Utc};

pub struct CentralSystem {
    ca: Box<dyn CertificationAuthority + Send>,
}

impl CentralSystem {
    pub fn build() -> Result<Box<dyn OcppCentralSystem + Send>, &'static str> {
        let settings = DefaultCertificationAuthoritySettings {
            directory: "/tmp/dummy-central-system/ca/".to_string(),
            new: true,
        };
        let mut ca = Box::new(DefaultCertificationAuthority::new(settings));
        let res = ca.init();

        match res {
            Ok(_) => {
                let cs = CentralSystem { ca };
                Ok(Box::new(cs))
            }
            Err(e) => {
                println!("{}", e);
                Err("failed to init Certification Authority")
            }
        }
    }
}

impl OcppCentralSystem for CentralSystem {
    fn make_response(&mut self, request: Message) -> Result<Vec<Message>, &str> {
        if request.command.is_none() {
            return Err("command is empty");
        }

        match (&request.role, request.command.as_ref().unwrap()) {
            (MessageType::Call, Command::BootNotification) => {
                self.make_boot_notification_response(request)
            }
            (MessageType::Call, Command::StatusNotification) => {
                self.make_status_notification_response(request)
            }
            (MessageType::Call, Command::Heartbeat) => self.make_heartbeat_response(request),
            (MessageType::Call, Command::SignCertificate) => {
                self.make_sign_certificate_response(request)
            }
            (MessageType::Call, Command::StartTransaction) => {
                self.make_start_transaction_response(request)
            }
            (MessageType::Call, Command::MeterValues) => self.make_meter_values_response(request),
            (MessageType::Call, Command::StopTransaction) => {
                self.make_stop_transaction_response(request)
            }
            (MessageType::Call, Command::Authorize) => self.make_authorize_response(request),
            (MessageType::Call, _) => self.make_default_answer(request),
            (_, _) => Err("no response"),
        }
    }
}

impl CentralSystem {
    fn make_boot_notification_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        let payload = object! {
            status : Status::Accepted,
            currentTime : self.make_timestamp(),
            interval:60
        };

        let response = Message::new(MessageType::CallResult, request.id, None, Some(payload));
        Ok(vec![response])
    }

    fn make_status_notification_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        let response = Message::new(MessageType::CallResult, request.id, None, Some(object! {}));
        Ok(vec![response])
    }

    fn make_start_transaction_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        let ts = (Utc::now().timestamp_millis() / 1000) as u32;
        let tag_info =
            object! { status : Status::Accepted , expiryDate : "2030-12-31T11:59:59.000000Z"};
        let status = object! { transactionId: ts, idTagInfo : tag_info };
        let response = Message::new(MessageType::CallResult, request.id, None, Some(status));
        Ok(vec![response])
    }

    fn make_stop_transaction_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        let tag_info =
            object! { status : Status::Accepted , expiryDate : "2030-12-31T11:59:59.000000Z"};
        let response = Message::new(MessageType::CallResult, request.id, None, Some(tag_info));
        Ok(vec![response])
    }

    fn make_authorize_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        let req_payload = request.payload.unwrap();
        let evses = &req_payload["evseId"];
        let token_info = object! { status : Status::Accepted , cacheExpiryDateTime : "2030-12-31T11:59:59.000000Z"};
        let data = object! { evseId : evses.clone(), idTokenInfo : token_info };
        let response = Message::new(MessageType::CallResult, request.id, None, Some(data));
        Ok(vec![response])
    }

    fn make_meter_values_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        let response = Message::new(MessageType::CallResult, request.id, None, Some(object! {}));
        Ok(vec![response])
    }

    fn make_heartbeat_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        let payload = object! {
            currentTime : self.make_timestamp(),
        };

        let response = Message::new(MessageType::CallResult, request.id, None, Some(payload));
        Ok(vec![response])
    }

    fn make_sign_certificate_response(&self, request: Message) -> Result<Vec<Message>, &str> {
        if request.payload.is_none() {
            return Err("payload is empty");
        }

        let mut result = Vec::<Message>::new();

        /* ACK */
        let ack_payload = object! { status : Status::Accepted };
        let ack = Message::new(MessageType::CallResult, request.id, None, Some(ack_payload));
        result.push(ack);

        /* Read CSR */
        let req_payload = request.payload.unwrap();
        let cert_type = req_payload["typeOfCertificate"]
            .as_str()
            .unwrap()
            .to_string();
        let csr_payload = req_payload["csr"].as_str().unwrap().to_string();

        println!("{} certificate requested", cert_type);

        let csr = CertificateSignRequest {
            data: Vec::from(csr_payload.as_bytes()),
            format: Format::PEM,
        };

        /* Generate certificate */
        if let Ok(cert) = self.ca.sign(csr) {
            let id = uuid::Uuid::new_v4().to_string();
            let resp_payload = object! {
                cert: array![hex::encode(cert[0].data.as_slice())],
                typeOfCertificate: cert_type,
            };
            let response = Message::new(
                MessageType::Call,
                id,
                Some(Command::CertificateSigned),
                Some(resp_payload),
            );
            result.push(response);
            return Ok(result);
        }
        Err("")
    }

    fn make_default_answer(&self, request: Message) -> Result<Vec<Message>, &str> {
        let response = Message::new(MessageType::CallResult, request.id, None, Some(object! {}));
        Ok(vec![response])
    }

    fn make_timestamp(&self) -> String {
        let now: DateTime<Utc> = Utc::now();
        now.to_rfc3339()
    }
}
