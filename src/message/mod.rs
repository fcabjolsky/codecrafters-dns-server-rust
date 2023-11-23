#[derive(Debug, Copy, Clone)]
pub struct DnsHeader {
    ///Packet Identifier (ID)
    ///16 bits	A random ID assigned to query packets. Response packets must reply with the same ID.
    id: u16,
    ///Query/Response Indicator (QR)
    ///1 bit	1 for a reply packet, 0 for a question packet.
    ///Operation Code (OPCODE)
    ///4 bits	Specifies the kind of query in a message.
    op_code: u8,
    ///Authoritative Answer (AA)
    ///1 bit	1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    authorative_answer: u8,
    ///Truncation (TC)
    ///1 bit	1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    truncation: u8,
    ///Recursion Desired (RD)
    ///1 bit	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    recursion_desired: u8,
    ///Recursion Available (RA)
    ///1 bit	Server sets this to 1 to indicate that recursion is available.
    recursion_available: u8,
    ///Reserved (Z)
    ///3 bits	Used by DNSSEC queries. At inception, it was reserved for future use.
    reserved: u8,
    ///Response Code (RCODE)
    ///4 bits	Response code indicating the status of the response.
    response_code: u8,
    ///Question Count (QDCOUNT)
    ///16 bits	Number of questions in the Question section.
    question_count: u16,
    ///Answer Record Count (ANCOUNT)
    ///16 bits	Number of records in the Answer section.
    answer_count: u16,
    ///Authority Record Count (NSCOUNT)
    ///16 bits	Number of records in the Authority section.
    authority_code: u16,
    ///Additional Record Count (ARCOUNT)
    ///16 bits	Number of records in the Additional section.
    additional_count: u16,
}

impl DnsHeader {
    fn new(data: &[u8]) -> DnsHeader {
        const OP_CODE_MASK: u8 = 0x0F;
        const RECURSION_DESIRED_MASK: u8 = 0x01;
        let op_code = (data[2] >> 3) & OP_CODE_MASK;
        let recursion_desired = data[2] & RECURSION_DESIRED_MASK;
        let question_count = (data[4] as u16) << 8 | (data[5] as u16);
        DnsHeader {
            id: DnsHeader::parse_id(data),
            op_code,
            authorative_answer: 0,
            truncation: 0,
            recursion_desired,
            recursion_available: 0,
            reserved: 0,
            response_code: if op_code == 0 { 0 } else { 4 },
            question_count,
            answer_count: question_count,
            authority_code: 0,
            additional_count: 0,
        }
    }

    pub fn get_header(self, is_question: bool) -> [u8; 12] {
        let mut header = [0; 12];
        let qr = if is_question { 0 } else { 1 };

        header[0] = self.id.to_be_bytes()[0];
        header[1] = self.id.to_be_bytes()[1];

        header[2] = (qr << 7)
            | (self.op_code << 3)
            | (self.authorative_answer << 2)
            | (self.truncation << 1)
            | self.recursion_desired;

        header[3] = (self.recursion_available << 7) | (self.reserved << 4) | self.response_code;

        header[4] = self.question_count.to_be_bytes()[0];
        header[5] = self.question_count.to_be_bytes()[1];

        header[6] = self.answer_count.to_be_bytes()[0];
        header[7] = self.answer_count.to_be_bytes()[1];

        header[8] = self.authority_code.to_be_bytes()[0];
        header[9] = self.authority_code.to_be_bytes()[1];

        header[10] = self.additional_count.to_be_bytes()[0];
        header[11] = self.additional_count.to_be_bytes()[1];

        return header;
    }
    pub fn parse_id(data: &[u8]) -> u16 {
        return ((data[0] as u16) << 8) | (data[1] as u16);
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    ///Name: A domain name, represented as a sequence of "labels" (more on this below)
    name: Vec<u8>,
    ///Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc., full list here)
    record_type: u16,
    ///Class: 2-byte int; usually set to 1 (full list here)
    class: u16,
}

impl DnsQuestion {
    pub fn get_question(&self) -> Vec<u8> {
        let mut question = vec![];
        question.extend(&self.name);
        question.push(self.record_type.to_be_bytes()[0]);
        question.push(self.record_type.to_be_bytes()[1]);

        question.push(self.class.to_be_bytes()[0]);
        question.push(self.class.to_be_bytes()[1]);

        return question;
    }

    fn new(label: Vec<u8>) -> DnsQuestion {
        return DnsQuestion {
            name: label,
            record_type: 1,
            class: 1,
        };
    }
}

#[derive(Debug)]
pub struct DnsAnswer {
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
    pub fn get_answer(&self) -> Vec<u8> {
        let mut final_answer = vec![];
        final_answer.extend(&self.name);

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

        final_answer.extend(&self.data);
        return final_answer;
    }

    fn new(label: Vec<u8>) -> DnsAnswer {
        DnsAnswer {
            name: label,
            answer_type: 1,
            class: 1,
            ttl: 60,
            length: 4,
            data: [8, 8, 8, 8].to_vec(),
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<Vec<u8>>,
    pub source: String,
    answer_begin: usize,
}

impl Message {
    pub fn new(data: &[u8], source: String) -> Message {
        let header = DnsHeader::new(data);
        let mut questions = vec![];
        let mut answers = vec![];
        let mut start = 12;
        for _ in 0..header.question_count {
            let (label, end) = Message::extract_label(&data, start);
            let question = DnsQuestion::new(label.clone());
            questions.push(question);

            let answer = DnsAnswer::new(label.clone());
            answers.push(answer.get_answer());
            start = end + 5;
        }
        return Message {
            header,
            questions,
            answers,
            source,
            answer_begin: start,
        };
    }

    pub fn extract_label(data: &[u8], start: usize) -> (Vec<u8>, usize) {
        const POINTER_IDENTIFIER_MASK: u8 = 0xC0;
        const POINTER_MASK: u16 = 0x3FFF;

        let mut label = vec![];
        for i in start..data.len() {
            let b = data[i];
            if b & POINTER_IDENTIFIER_MASK == POINTER_IDENTIFIER_MASK {
                let mut pointer = (b as u16) << 8 | data[i + 1] as u16;
                pointer &= POINTER_MASK;
                let (pointed_label, _) = Message::extract_label(data, pointer as usize);
                label.extend(pointed_label);
                return (label, i);
            }
            label.push(b);
            if b == 0 {
                return (label, i);
            }
        }
        return (label, start); //should never happen
    }

    pub fn get_final_packet(&self) -> Vec<u8> {
        let mut packet: Vec<u8> = vec![];
        packet.extend_from_slice(&self.header.get_header(false));
        for question in &self.questions {
            packet.extend(question.get_question());
        }

        for answer in &self.answers {
            packet.extend(answer);
        }
        return packet;
    }

    pub fn get_packets_to_forward(&self) -> Vec<Vec<u8>> {
        let mut packets = vec![];
        for question in &self.questions {
            let mut packet: Vec<u8> = vec![];
            packet.extend_from_slice(&self.header.get_header(true));
            packet.extend(question.get_question());
            packets.push(packet);
        }
        return packets;
    }

    pub fn parse_answer(&mut self, data: &[u8]) {
        if self.answer_begin > data.len() {
            return;
        }
        self.answers = vec![];
        self.answers.push(data[self.answer_begin..].to_vec());
    }

    pub fn is_ready(&self) -> bool {
        return self.header.question_count as usize == self.answers.len();
    }

    pub fn get_id(&self) -> u16 {
        return self.header.id;
    }
}

