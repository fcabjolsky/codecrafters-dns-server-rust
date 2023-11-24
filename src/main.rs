// Uncomment this block to pass the first stage
mod message;
use message::*;
use std::collections::HashMap;
use std::env;
use std::net::UdpSocket;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let args: Vec<String> = env::args().collect();
    let resolver_address: String = args[2].clone();

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    let mut messages: HashMap<u16, Message> = HashMap::new();
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);
                println!(
                    "Received {} bytes from {} {}",
                    size, source, resolver_address
                );
                if source.to_string() != resolver_address {
                    let message = Message::new(&buf, source.to_string());
                    let packets = message.get_packets_to_forward();
                    for packet in packets {
                        udp_socket
                            .send_to(&packet, &resolver_address)
                            .expect("faild to forward the UDP packet");
                    }
                    messages.insert(message.get_id(), message);
                } else {
                    let id = DnsHeader::parse_id(&buf);
                    let message = messages.get_mut(&id).expect("Message not found");
                    message.parse_answer(&buf[0..size]);
                    if message.is_ready() {
                        let packet = message.get_final_packet();
                        udp_socket
                            .send_to(packet.as_slice(), &message.source)
                            .expect("failed to send response");
                        messages.remove(&id);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
        buf.fill(0);
    }
}
