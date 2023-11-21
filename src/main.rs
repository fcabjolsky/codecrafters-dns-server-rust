// Uncomment this block to pass the first stage
use std::net::UdpSocket;

#[derive(Debug)]
struct DnsHeader {
    /// Packet Identifier (ID)	16 bits	A random ID assigned to query packets. Response packets must reply with the same ID.
    /// Expected value: 1234.
    id: u16,
    /// Query/Response Indicator (QR)	1 bit	1 for a reply packet, 0 for a question packet.
    /// Expected value: 1.
    qr: u8,
    ///Operation Code (OPCODE)	4 bits	Specifies the kind of query in a message.
    ///Expected value: 0.
    opcode: u8,
    ///Authoritative Answer (AA)	1 bit	1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    ///Expected value: 0.
    aa: u8,
    ///Truncation (TC)	1 bit	1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    ///Expected value: 0.
    tc: u8,
    ///Recursion Desired (RD)	1 bit	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    ///Expected value: 0.
    rd: u8,
    ///Recursion Available (RA)	1 bit	Server sets this to 1 to indicate that recursion is available.
    ///Expected value: 0.
    ra: u8,
    ///Reserved (Z)	3 bits	Used by DNSSEC queries. At inception, it was reserved for future use.
    ///Expected value: 0.
    z: u8,
    ///Response Code (RCODE)	4 bits	Response code indicating the status of the response.
    ///Expected value: 0 (no error).
    rcode: u8,
    ///Question Count (QDCOUNT)	16 bits	Number of questions in the Question section.
    ///Expected value: 0.
    qdcount: u16,
    ///Answer Record Count (ANCOUNT)	16 bits	Number of records in the Answer section.
    ///Expected value: 0.
    ancount: u16,
    ///Authority Record Count (NSCOUNT)	16 bits	Number of records in the Authority section.
    ///Expected value: 0.
    nscount: u16,
    ///Additional Record Count (ARCOUNT)	16 bits	Number of records in the Additional section.
    ///Expected value: 0
    arcount: u16,
}

impl DnsHeader {
    fn generate_reply(self) -> [u8; 12] {
        let mut header = [0; 12];

        header[0] = self.id.to_be_bytes()[0];
        header[1] = self.id.to_be_bytes()[1];

        header[2] = (self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd;

        header[3] = (self.ra << 7) | (self.z << 4) | self.rcode;

        header[4] = self.qdcount.to_be_bytes()[0];
        header[5] = self.qdcount.to_be_bytes()[1];

        header[6] = self.ancount.to_be_bytes()[0];
        header[7] = self.ancount.to_be_bytes()[1];

        header[8] = self.nscount.to_be_bytes()[0];
        header[9] = self.nscount.to_be_bytes()[1];

        header[10] = self.arcount.to_be_bytes()[0];
        header[11] = self.arcount.to_be_bytes()[1];

        return header;
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);
                println!("Received {} bytes from {}", size, source);
                let response = DnsHeader {
                    id: 1234,
                    qr: 1,
                    opcode: 0,
                    aa: 0,
                    tc: 0,
                    rd: 0,
                    ra: 0,
                    z: 0,
                    rcode: 0,
                    qdcount: 0,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                };
                udp_socket
                    .send_to(&response.generate_reply(), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
