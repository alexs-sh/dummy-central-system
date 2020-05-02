pub mod cs;
pub mod ocpp;
pub mod x509;

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::spawn;

use chrono::prelude::*;

use tungstenite::accept_hdr;
use tungstenite::handshake::server::{Request, Response};

#[macro_use]
extern crate json;

fn get_rfc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, false)
}

fn ws_cycle(cs: Box<dyn ocpp::CentralSystem + Send>) {
    let server = TcpListener::bind("0.0.0.0:8080").unwrap();

    let shared_cs = Arc::new(Mutex::new(cs));

    for stream in server.incoming() {
        let current_cs = Arc::clone(&shared_cs);
        spawn(move || {
            let callback = |_: &Request, mut resp: Response| {
                println!("Received a new WS handshake");
                let headers = resp.headers_mut();
                headers.append("Sec-WebSocket-Protocol", "ocpp1.6".parse().unwrap());
                Ok(resp)
            };

            let mut websocket = accept_hdr(stream.unwrap(), callback).unwrap();

            loop {
                let input = websocket.read_message();
                if input.is_err() {
                    println!("Close connection");
                    let _ = websocket.close(None);
                    break;
                }

                let msg_in = input.unwrap();
                if msg_in.is_text() {
                    println!();
                    println!("[{}] CP: {}", get_rfc_now(), msg_in);
                    println!();

                    let ocpp_req = ocpp::unpack_message(msg_in.to_text().unwrap()).unwrap();
                    let mut cs = current_cs.lock().unwrap();
                    if let Ok(ocpp_resp) = cs.make_response(ocpp_req) {
                        for r in ocpp_resp {
                            let msg_out = tungstenite::protocol::Message::Text(
                                ocpp::pack_message(r).unwrap(),
                            );
                            println!();
                            println!("[{}] CS: {}", get_rfc_now(), msg_out);
                            println!();
                            let _ = websocket.write_message(msg_out);
                        }
                    }
                }
            }
        });
    }
}

fn main() {
    let cs = cs::CentralSystem::build().unwrap();
    ws_cycle(cs)
}
