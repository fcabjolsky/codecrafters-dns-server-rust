// Uncomment this block to pass the first stage
use std::net::UdpSocket;

#[derive(Debug, Clone)]
struct Label {
    encoded_label: Vec<u8>,
}

impl Label {
    fn new(name: String) -> Self {
        let splitted: Vec<&str> = name.split(".").collect();
        let mut full_label: Vec<u8> = vec![];
        full_label.push(splitted[0].len() as u8);
        for b in splitted[0].as_bytes() {
            full_label.push(b.clone());
        }
        full_label.push(splitted[1].len() as u8);
        for b in splitted[1].as_bytes() {
            full_label.push(b.clone());
        }
        full_label.push(0x00);
        return Label {
            encoded_label: full_label,
        };
    }
}

#[derive(Debug, Copy, Clone)]
struct DnsHeader {
    /// Packet Identifier (ID)	16 bits	A random ID assigned to query packets. Response packets must reply with the same ID.
    id: u16,
    /// Query/Response Indicator (QR)	1 bit	1 for a reply packet, 0 for a question packet.
    qr: u8,
    ///Operation Code (OPCODE)	4 bits	Specifies the kind of query in a message.
    opcode: u8,
    ///Authoritative Answer (AA)	1 bit	1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    aa: u8,
    ///Truncation (TC)	1 bit	1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    tc: u8,
    ///Recursion Desired (RD)	1 bit	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    rd: u8,
    ///Recursion Available (RA)	1 bit	Server sets this to 1 to indicate that recursion is available.
    ra: u8,
    ///Reserved (Z)	3 bits	Used by DNSSEC queries. At inception, it was reserved for future use.
    z: u8,
    ///Response Code (RCODE)	4 bits	Response code indicating the status of the response.
    rcode: u8,
    ///Question Count (QDCOUNT)	16 bits	Number of questions in the Question section.
    qdcount: u16,
    ///Answer Record Count (ANCOUNT)	16 bits	Number of records in the Answer section.
    ancount: u16,
    ///Authority Record Count (NSCOUNT)	16 bits	Number of records in the Authority section.
    nscount: u16,
    ///Additional Record Count (ARCOUNT)	16 bits	Number of records in the Additional section.
    arcount: u16,
}

impl DnsHeader {
    fn get_header(self) -> [u8; 12] {
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

#[derive(Debug)]
struct DnsQuestion {
    ///Name: A domain name, represented as a sequence of "labels" (more on this below)
    name: Vec<u8>,
    ///Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list here)
    record_type: u16,
    ///Class: 2-byte int; usually set to 1 (full list here)
    class: u16,
}

impl DnsQuestion {
    fn get_question(self) -> Vec<u8> {
        let mut question = vec![];
        self.name.clone_into(&mut question);
        question.push(self.record_type.to_be_bytes()[0]);
        question.push(self.record_type.to_be_bytes()[1]);

        question.push(self.class.to_be_bytes()[0]);
        question.push(self.class.to_be_bytes()[1]);

        return question;
    }

    fn add_label(&mut self, label: &Label) {
        self.name = label.encoded_label.clone();
    }
}

#[derive(Debug)]
struct DnsAnswer {
    ///Name	Label Sequence	The domain name encoded as a sequence of labels.
    name: Vec<u8>,
    ///Type	2-byte Integer	1 for an A record, 5 for a CNAME record etc., full list here
    answer_type: u16,
    ///Class	2-byte Integer	Usually set to 1 (full list here)
    class: u16,
    ///TTL (Time-To-Live)	4-byte Integer	The duration in seconds a record can be cached before requerying.
    ttl: u32,
    ///Length (RDLENGTH)	2-byte Integer	Length of the RDATA field in bytes.
    length: u16,
    ///Data (RDATA)	Variable	Data specific to the record type.
    data: Vec<u8>,
}

impl DnsAnswer {
    fn get_answer(self) -> Vec<u8> {
        let mut final_answer = vec![];
        final_answer.extend(self.name);

        final_answer.push(self.answer_type.to_be_bytes()[0]);
        final_answer.push(self.answer_type.to_be_bytes()[1]);

        final_answer.push(self.class.to_be_bytes()[0]);
        final_answer.push(self.class.to_be_bytes()[1]);

        final_answer.push(self.ttl.to_be_bytes()[0]);
        final_answer.push(self.ttl.to_be_bytes()[1]);
        final_answer.push(self.ttl.to_be_bytes()[2]);
        final_answer.push(self.ttl.to_be_bytes()[3]);

        final_answer.push(self.length.to_be_bytes()[0]);
        final_answer.push(self.length.to_be_bytes()[1]);

        final_answer.extend(self.data);
        return final_answer;
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    let label = Label::new(String::from("codecrafters.io"));
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);
                println!("Received {} bytes from {}", size, source);
                let header = DnsHeader {
                    id: 1234,
                    qr: 1,
                    opcode: 0,
                    aa: 0,
                    tc: 0,
                    rd: 0,
                    ra: 0,
                    z: 0,
                    rcode: 0,
                    qdcount: 1,
                    ancount: 1,
                    nscount: 0,
                    arcount: 0,
                };
                let mut packet: Vec<u8> = vec![];
                packet.extend_from_slice(&header.get_header());

                let mut question = DnsQuestion {
                    name: vec![],
                    record_type: 1,
                    class: 1,
                };
                question.add_label(&label);
                packet.extend(question.get_question());

                let answer = DnsAnswer {
                    name: label.encoded_label.clone(),
                    answer_type: 1,
                    class: 1,
                    ttl: 60,
                    length: 4,
                    data: "8.8.8.8".as_bytes().to_vec(),
                };
                packet.extend(answer.get_answer());

                udp_socket
                    .send_to(packet.as_slice(), source)
                    .expect("failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
