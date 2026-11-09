//! QUIC Initial recognition and the adaptive-mode "prime" datagram (port of
//! the pure half of `src/QuicStrategy.cpp`).

const QUIC_V2: u32 = 0x6B33_43CF;
const MINIMUM_INITIAL_SIZE: usize = 1200;

/// A client Initial: at least 1200 bytes, long header with the fixed bit, a
/// non-zero version, and the Initial packet type for that version.
pub fn looks_like_initial(payload: &[u8]) -> bool {
    if payload.len() < MINIMUM_INITIAL_SIZE {
        return false;
    }
    let first = payload[0];
    if first & 0xC0 != 0xC0 {
        return false; // long header + fixed bit
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        return false; // version negotiation, not Initial
    }
    let packet_type = first & 0x30;
    if version == QUIC_V2 {
        packet_type == 0x10
    } else {
        packet_type == 0x00
    }
}

/// 32 random bytes whose QUIC fixed bit is clear, so a compliant server
/// ignores the datagram while a middlebox still sees traffic on the flow.
pub fn build_prime_payload(random: [u8; 32]) -> Vec<u8> {
    let mut payload = random.to_vec();
    payload[0] &= 0x3F;
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_quic_v1_initial_and_rejects_short_datagrams() {
        let mut initial = vec![0u8; 1200];
        initial[0] = 0xC0;
        initial[4] = 1;
        assert!(looks_like_initial(&initial));
        assert!(!looks_like_initial(&initial[..1199]));
        initial[0] = 0x40;
        assert!(!looks_like_initial(&initial));
    }

    #[test]
    fn recognizes_quic_v2_initial_type() {
        let mut initial = vec![0u8; 1200];
        initial[1..5].copy_from_slice(&QUIC_V2.to_be_bytes());
        initial[0] = 0xD0; // v2 Initial is type 0b01
        assert!(looks_like_initial(&initial));
        initial[0] = 0xC0;
        assert!(!looks_like_initial(&initial));
    }

    #[test]
    fn prime_payload_cannot_be_parsed_as_quic() {
        let prime = build_prime_payload([0xFF; 32]);
        assert_eq!(prime.len(), 32);
        assert_eq!(prime[0] & 0x40, 0);
    }
}
