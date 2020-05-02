use std::convert::TryFrom;

pub enum MessageType {
    Call,
    CallResult,
    CallError,
}

impl TryFrom<u8> for MessageType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            2 => Ok(MessageType::Call),
            3 => Ok(MessageType::CallResult),
            4 => Ok(MessageType::CallError),
            _ => Err(()),
        }
    }
}

impl ToString for MessageType {
    fn to_string(&self) -> String {
        match self {
            MessageType::Call => "Call".to_string(),
            MessageType::CallResult => "CallResult".to_string(),
            MessageType::CallError => "CallError".to_string(),
        }
    }
}

pub enum Command {
    BootNotification,
    StatusNotification,
    Heartbeat,
    SignCertificate,
    CertificateSigned,
    StartTransaction,
    MeterValues,
    StopTransaction,
    Authorize,
}

impl ToString for Command {
    fn to_string(&self) -> String {
        match self {
            Command::BootNotification => "BootNotification".to_string(),
            Command::StatusNotification => "StatusNotification".to_string(),
            Command::Heartbeat => "Heartbeat".to_string(),
            Command::SignCertificate => "SignCertificate".to_string(),
            Command::CertificateSigned => "CertificateSigned".to_string(),
            Command::StartTransaction => "StartTransaction".to_string(),
            Command::MeterValues => "MeterValues".to_string(),
            Command::StopTransaction => "StopTransaction".to_string(),
            Command::Authorize => "Authorize".to_string(),
        }
    }
}

impl TryFrom<&str> for Command {
    type Error = ();
    fn try_from(value: &str) -> Result<Self, ()> {
        if value.eq_ignore_ascii_case("BootNotification") {
            Ok(Command::BootNotification)
        } else if value.eq_ignore_ascii_case("StatusNotification") {
            Ok(Command::StatusNotification)
        } else if value.eq_ignore_ascii_case("Heartbeat") {
            Ok(Command::Heartbeat)
        } else if value.eq_ignore_ascii_case("SignCertificate") {
            Ok(Command::SignCertificate)
        } else if value.eq_ignore_ascii_case("CertificateSigned") {
            Ok(Command::CertificateSigned)
        } else if value.eq_ignore_ascii_case("StartTransaction") {
            Ok(Command::StartTransaction)
        } else if value.eq_ignore_ascii_case("MeterValues") {
            Ok(Command::MeterValues)
        } else if value.eq_ignore_ascii_case("StopTransaction") {
            Ok(Command::StopTransaction)
        } else if value.eq_ignore_ascii_case("Authorize") {
            Ok(Command::Authorize)
        } else {
            Err(())
        }
    }
}

pub enum Status {
    Accepted,
    Rejected,
}

impl ToString for Status {
    fn to_string(&self) -> String {
        match self {
            Status::Accepted => "Accepted".to_string(),
            Status::Rejected => "Rejected".to_string(),
        }
    }
}

impl From<Status> for json::JsonValue {
    fn from(status: Status) -> Self {
        match status {
            Status::Accepted => json::JsonValue::String("Accepted".to_string()),
            Status::Rejected => json::JsonValue::String("Rejected".to_string()),
        }
    }
}

pub struct Message {
    pub role: MessageType,
    pub id: String,
    pub command: Option<Command>,
    pub payload: Option<json::JsonValue>,
}

impl Message {
    pub fn new(
        role: MessageType,
        id: String,
        command: Option<Command>,
        payload: Option<json::JsonValue>,
    ) -> Message {
        Message {
            role,
            id,
            command,
            payload,
        }
    }
}

pub trait CentralSystem {
    fn make_response(&mut self, request: Message) -> Result<Vec<Message>, &str>;
}

pub fn unpack_message(raw: &str) -> Result<Message, &str> {
    const TYPE_INDEX: usize = 0;
    const ID_INDEX: usize = 1;
    const COMMAND_INDEX: usize = 2;
    const PAYLOAD_INDEX: usize = 3;

    let payload = json::parse(raw);

    if payload.is_err() {
        return Err("can't parse");
    }

    let mut data = payload.unwrap();
    if data.len() <= ID_INDEX {
        return Err("invalid len");
    }

    let type_raw = data[TYPE_INDEX].as_u8().ok_or("type is invalid").unwrap();
    let id_raw = data[ID_INDEX].as_str().ok_or("id is invalid").unwrap();
    if id_raw.is_empty() {
        return Err("id is empty");
    }

    let msg_type = MessageType::try_from(type_raw)
        .or(Err("type is invalid"))
        .unwrap();
    let msg_id = id_raw.to_string();
    let msg_command = if data.len() > COMMAND_INDEX {
        if let Some(unpacked) = data[COMMAND_INDEX].as_str() {
            Command::try_from(unpacked).ok()
        } else {
            None
        }
    } else {
        None
    };

    let msg_payload = if data.len() > PAYLOAD_INDEX {
        Some(data[PAYLOAD_INDEX].take())
    } else {
        None
    };

    Ok(Message::new(msg_type, msg_id, msg_command, msg_payload))
}

pub fn pack_message(message: Message) -> Result<String, ()> {
    let msg_type = match message.role {
        MessageType::Call => 2,
        MessageType::CallResult => 3,
        MessageType::CallError => 4,
    };

    let mut data = array![msg_type, message.id];

    if let Some(cmd) = message.command {
        let _ = data.push(cmd.to_string());
    }

    if let Some(mut payload) = message.payload {
        let _ = data.push(payload.take());
    }

    Ok(json::stringify(data))
}
