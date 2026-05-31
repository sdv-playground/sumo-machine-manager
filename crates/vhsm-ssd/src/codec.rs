/// Binary frame encoding/decoding for the vHSM wire protocol (v2).
///
/// Request:  [3] magic + [1] version + [4] op + [4] session_id + [4] payload_len + [N] payload
/// Response: [3] magic + [1] version + [4] op + [4] session_id + [4] payload_len + [4] status + [N] payload
use std::io::{self, Read, Write};

use crate::proto::*;

/// Read a complete request from the stream.
pub fn read_request(r: &mut dyn Read) -> io::Result<Request> {
    let mut hdr = [0u8; REQUEST_HEADER_SIZE];
    read_exact(r, &mut hdr)?;

    // Validate magic
    if hdr[0..3] != VHSM_MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
    }
    // Validate version
    if hdr[3] != VHSM_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported version: {}", hdr[3]),
        ));
    }

    let op = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let session_id = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let payload_len = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as usize;

    if payload_len > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "payload too large",
        ));
    }

    // Read payload
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact(r, &mut payload)?;
    }

    Ok(Request {
        op,
        session_id,
        payload,
    })
}

/// Write a complete response to the stream.
pub fn write_response(w: &mut dyn Write, resp: &Response) -> io::Result<()> {
    let mut hdr = [0u8; RESPONSE_HEADER_SIZE];
    hdr[0..3].copy_from_slice(&VHSM_MAGIC);
    hdr[3] = VHSM_VERSION;
    hdr[4..8].copy_from_slice(&resp.op.to_le_bytes());
    hdr[8..12].copy_from_slice(&resp.session_id.to_le_bytes());
    hdr[12..16].copy_from_slice(&(resp.payload.len() as u32).to_le_bytes());
    hdr[16..20].copy_from_slice(&resp.status.to_le_bytes());

    w.write_all(&hdr)?;
    if !resp.payload.is_empty() {
        w.write_all(&resp.payload)?;
    }
    w.flush()
}

/// Read exactly `buf.len()` bytes, handling partial reads.
fn read_exact(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        match r.read(&mut buf[pos..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ))
            }
            Ok(n) => pos += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request_response() {
        // Build a request
        let req = Request {
            op: Op::Sign as u32,
            session_id: 42,
            payload: vec![1, 2, 3, 4],
        };

        // Encode to bytes
        let mut buf = Vec::new();
        buf.extend_from_slice(&VHSM_MAGIC);
        buf.push(VHSM_VERSION);
        buf.extend_from_slice(&req.op.to_le_bytes());
        buf.extend_from_slice(&req.session_id.to_le_bytes());
        buf.extend_from_slice(&(req.payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(&req.payload);

        let parsed = read_request(&mut &buf[..]).unwrap();
        assert!(parsed.op == Op::Sign as u32);
        assert!(parsed.session_id == 42);
        assert!(parsed.payload == vec![1, 2, 3, 4]);

        // Test response
        let resp = Response::ok(Op::Sign as u32, 42, vec![5, 6, 7]);
        let mut out = Vec::new();
        write_response(&mut out, &resp).unwrap();
        assert_eq!(out.len(), RESPONSE_HEADER_SIZE + 3);
        assert_eq!(&out[0..3], &VHSM_MAGIC);
        assert_eq!(
            u32::from_le_bytes([out[4], out[5], out[6], out[7]]),
            Op::Sign as u32
        );
    }

    /// Helper: build a valid request header + payload.
    fn make_req_bytes(op: u32, session_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&VHSM_MAGIC);
        buf.push(VHSM_VERSION);
        buf.extend_from_slice(&op.to_le_bytes());
        buf.extend_from_slice(&session_id.to_le_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn read_request_rejects_bad_magic() {
        let mut bytes = make_req_bytes(Op::Sign as u32, 0, &[]);
        bytes[0] = b'X'; // clobber magic
        let err = match read_request(&mut &bytes[..]) {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn read_request_rejects_bad_version() {
        let mut bytes = make_req_bytes(Op::Sign as u32, 0, &[]);
        bytes[3] = 0xFF; // clobber version
        let err = match read_request(&mut &bytes[..]) {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("unsupported version"));
    }

    #[test]
    fn read_request_rejects_payload_over_max() {
        // Build header that claims payload_len = MAX_PAYLOAD + 1.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&VHSM_MAGIC);
        bytes.push(VHSM_VERSION);
        bytes.extend_from_slice(&(Op::Sign as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let oversized = (MAX_PAYLOAD as u32).saturating_add(1);
        bytes.extend_from_slice(&oversized.to_le_bytes());
        let err = match read_request(&mut &bytes[..]) {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("payload too large"));
    }

    #[test]
    fn read_request_rejects_truncated_header() {
        // Header is 16 bytes; give only 8.
        let bytes = [0u8; 8];
        let err = match read_request(&mut &bytes[..]) {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_request_rejects_truncated_payload() {
        // Header declares 16-byte payload but we provide 4 bytes.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&VHSM_MAGIC);
        bytes.push(VHSM_VERSION);
        bytes.extend_from_slice(&(Op::Sign as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let err = match read_request(&mut &bytes[..]) {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_request_accepts_zero_length_payload() {
        let bytes = make_req_bytes(Op::GetPubkey as u32, 0, &[]);
        let req = read_request(&mut &bytes[..]).unwrap();
        assert!(req.op == Op::GetPubkey as u32);
        assert!(req.payload.is_empty());
    }

    #[test]
    fn write_response_serializes_status_field() {
        // Error responses set status != 0 and clear payload.
        let resp = Response::err(Op::Sign as u32, 42, StatusCode::PermissionDeny);
        let mut out = Vec::new();
        write_response(&mut out, &resp).unwrap();
        // payload_len = 0
        assert_eq!(u32::from_le_bytes([out[12], out[13], out[14], out[15]]), 0);
        // status
        let status = u32::from_le_bytes([out[16], out[17], out[18], out[19]]);
        assert_eq!(status, StatusCode::PermissionDeny as u32);
        assert_eq!(out.len(), RESPONSE_HEADER_SIZE);
    }

    #[test]
    fn roundtrip_request_with_empty_payload() {
        let bytes = make_req_bytes(Op::GetHandleInfo as u32, 7, &[]);
        let req = read_request(&mut &bytes[..]).unwrap();
        assert!(req.session_id == 7);
        assert!(req.payload.is_empty());
    }
}
