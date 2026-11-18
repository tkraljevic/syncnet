#[cfg(test)]
mod tests {
    use crate::identity::{parse_public_key, public_key_to_base64};
    use crate::pairing::{SAS_NONCE_LEN, compute_sas_code, compute_sas_commit};
    use crate::transport::punch::{KIND_PUNCH, PunchKeys};
    use crate::trust::{NetworkKey, SignedVersionEnvelope};
    use crate::wire::frame::{DEFAULT_MAX_FRAME_LEN, read_frame, write_frame};
    use crate::wire::signal::{
        ReplayCache, SIGNAL_KIND_POZIV, SignedSignalMessage, verify_signed_signal,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::SigningKey;
    use std::io::Cursor;

    const SEED_A: [u8; 32] = [0x01; 32];
    const SEED_B: [u8; 32] = [0x02; 32];
    const SEED_NET: [u8; 32] = [0x10; 32];

    const EXPECTED_PUB_A: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
    const EXPECTED_PUB_B: &str = "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=";
    const EXPECTED_PUB_NET: &str = "XJxt8mHJy4QEdXdqrvzZRLQFMo+rKPmzqV70BJDT3oQ=";

    #[test]
    fn reproducible_go_fixture_binds_all_version_fields() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/go-vectors.json")).unwrap();
        assert_eq!(f["public_a"], EXPECTED_PUB_A);
        assert_eq!(f["public_b"], EXPECTED_PUB_B);
        assert_eq!(f["public_network"], EXPECTED_PUB_NET);
        assert_eq!(f["sas"], "087427");
        let seed = SigningKey::from_bytes(&SEED_A);
        let v = SignedVersionEnvelope {
            version_id: "0199c82c-0000-7000-8000-000000000001".into(),
            entity: "shopping_lists".into(),
            entity_id: "list-1".into(),
            node_id: EXPECTED_PUB_A.into(),
            supersedes: String::new(),
            archived: false,
            channel: "list:list-1".into(),
            created_at: "2025-10-09T08:53:20Z".into(),
            created_at_unix: 1760000000,
            schema_version: 1,
            author_pub_key: EXPECTED_PUB_A.into(),
            grant_ref: "grant-1".into(),
            payload: r#"{"name":"Subota"}"#.into(),
            signature: f["version_signature"].as_str().unwrap().into(),
        };
        assert_eq!(
            std::str::from_utf8(&v.canonical_signing_bytes()).unwrap(),
            f["version_bytes"].as_str().unwrap()
        );
        v.verify_signature().expect("verify version signed by Go");
        assert_eq!(v.clone().sign(&seed).signature, v.signature);
    }

    #[test]
    fn signed_extreme_signal_timestamp_is_rejected_without_overflow() {
        use crate::wire::signal::{SignalBody, SignalError};
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/go-vectors.json")).unwrap();
        let mut body: SignalBody =
            serde_json::from_str(f["signal_body"].as_str().unwrap()).unwrap();
        body.izdano = i64::MIN;
        let sender = SigningKey::from_bytes(&SEED_A);
        let target = SigningKey::from_bytes(&SEED_B).verifying_key();
        let rendezvous = SigningKey::from_bytes(&SEED_NET).verifying_key();
        let msg = SignedSignalMessage::sign(&sender, "list2cart", SIGNAL_KIND_POZIV, body);
        assert_eq!(
            verify_signed_signal(
                "list2cart",
                &msg,
                &target,
                &rendezvous,
                i64::MAX,
                &mut ReplayCache::default(),
                |_, _| true
            ),
            Err(SignalError::ClockSkew)
        );
    }

    #[test]
    fn go_vector_public_keys_base64_roundtrip() {
        let sk_a = SigningKey::from_bytes(&SEED_A);
        let sk_b = SigningKey::from_bytes(&SEED_B);
        let sk_net = SigningKey::from_bytes(&SEED_NET);

        let b64_a = public_key_to_base64(sk_a.verifying_key().as_bytes());
        let b64_b = public_key_to_base64(sk_b.verifying_key().as_bytes());
        let b64_net = public_key_to_base64(sk_net.verifying_key().as_bytes());

        assert_eq!(b64_a, EXPECTED_PUB_A);
        assert_eq!(b64_b, EXPECTED_PUB_B);
        assert_eq!(b64_net, EXPECTED_PUB_NET);

        assert_eq!(parse_public_key(&b64_a).unwrap(), sk_a.verifying_key());
        assert_eq!(parse_public_key(&b64_b).unwrap(), sk_b.verifying_key());
    }

    #[test]
    fn go_vector_sas_commit_and_leading_zero_code() {
        let sk_a = SigningKey::from_bytes(&SEED_A);
        let sk_b = SigningKey::from_bytes(&SEED_B);

        let mut caller_nonce = [0u8; SAS_NONCE_LEN];
        let mut listener_nonce = [0u8; SAS_NONCE_LEN];
        for j in 0..SAS_NONCE_LEN {
            caller_nonce[j] = j as u8;
            listener_nonce[j] = (0x80 + j) as u8;
        }

        let commit = compute_sas_commit("list2cart", &caller_nonce);
        assert_eq!(
            hex::encode(commit),
            "e7701f40d4dad8dec9571cf2d3ea6485e2db952117d4311b04fa9c79f9a715ee"
        );

        let code = compute_sas_code(
            "list2cart",
            sk_a.verifying_key().as_bytes(),
            sk_b.verifying_key().as_bytes(),
            &caller_nonce,
            &listener_nonce,
        );
        assert_eq!(code, "087427");
    }

    #[test]
    fn go_vector_hkdf_hmac_punch_packet() {
        let sk_a = SigningKey::from_bytes(&SEED_A);
        let sk_b = SigningKey::from_bytes(&SEED_B);
        let sess_hex = "00112233445566778899aabbccddeeff";
        let call_secret = [0xAAu8; 32];
        let resp_secret = [0xBBu8; 32];

        let ka = PunchKeys::derive(
            "list2cart",
            sess_hex,
            &call_secret,
            &resp_secret,
            sk_a.verifying_key().as_bytes(),
            sk_b.verifying_key().as_bytes(),
        )
        .expect("derive keys");

        assert_eq!(ka.dir, 1);
        assert_eq!(
            hex::encode(ka.send_key),
            "fe5303ce10bf959dfa4a7aef705f57be562a63f35aa065603c9c93c45fa073b8"
        );

        let pkt = ka.build_packet(KIND_PUNCH, 7);
        assert_eq!(
            hex::encode(pkt),
            "1001010000112233445566778899aabbccddeeff0000000000000007ee343368b74a4231be6c2d32dc5f95ffdf964a835a77e6f8d9ff7b7601551674"
        );
    }

    #[test]
    fn go_vector_ovlast_canonical_bytes_and_signature() {
        let sk_a = SigningKey::from_bytes(&SEED_A);
        let sk_net = SigningKey::from_bytes(&SEED_NET);
        let net = NetworkKey::from_signing_key("Obitelj", sk_net);

        let ovlast = net
            .issue_ovlast(
                "admin-1",
                &sk_a.verifying_key(),
                "root",
                1_760_000_000,
                3600,
            )
            .expect("ovlast");

        assert_eq!(
            String::from_utf8(ovlast.signed_bytes()).unwrap(),
            r#"{"v":"ovlast/1","network":"XJxt8mHJy4QEdXdqrvzZRLQFMo+rKPmzqV70BJDT3oQ=","deviceId":"admin-1","deviceKey":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","issuedBy":"root","issuedAt":1760000000,"expiresAt":1760003600}"#
        );
        assert_eq!(
            ovlast.signature,
            "Iqu70hDKOqhQHoK6e92ef9YGihpCtdOz9ishVS4GO7++GUYmK3c7E5OwySr2FCXGUbstb2ztoaGN52tY9Z9DAA=="
        );
        ovlast
            .verify(&net.public, 1_760_000_100)
            .expect("verify vector ovlast");
    }

    #[test]
    fn go_vector_signal_raw_body_signature_and_framing() {
        let sk_a = SigningKey::from_bytes(&SEED_A);
        let sk_b = SigningKey::from_bytes(&SEED_B);
        let sk_net = SigningKey::from_bytes(&SEED_NET);

        let raw_body = format!(
            r#"{{"ver":1,"sesija":"00112233445566778899aabbccddeeff","od":"{EXPECTED_PUB_A}","za":"{EXPECTED_PUB_B}","sastajaliste":"{EXPECTED_PUB_NET}","izdano":1760000000}}"#
        );
        let sig_bytes = STANDARD
            .decode("h6LAu2ormAjdnAPXggIWhMZn5adijcOK+zky6bdU1pjW6w64+7afNCZmgMFYaEnXZkcme/XJm9/Zj1cVZRqQDQ==")
            .unwrap();

        let msg = SignedSignalMessage {
            kind: SIGNAL_KIND_POZIV.to_owned(),
            tijelo: raw_body.into_bytes(),
            potpis: sig_bytes,
        };

        let mut cache = ReplayCache::default();
        let body = verify_signed_signal(
            "list2cart",
            &msg,
            &sk_b.verifying_key(),
            &sk_net.verifying_key(),
            1_760_000_010,
            &mut cache,
            |vk, _| vk == &sk_a.verifying_key(),
        )
        .expect("verify Go-signed signal vector");
        assert_eq!(body.sesija, "00112233445566778899aabbccddeeff");

        // Also test 4-byte big-endian framing over serialized signal wrapper
        let wire_json = serde_json::to_vec(&msg).unwrap();
        let mut framed = Vec::new();
        write_frame(&mut framed, &wire_json, DEFAULT_MAX_FRAME_LEN).unwrap();
        assert_eq!(
            u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize,
            wire_json.len()
        );
        let mut cur = Cursor::new(framed);
        let unframed = read_frame(&mut cur, DEFAULT_MAX_FRAME_LEN).unwrap();
        assert_eq!(unframed, wire_json);
    }
}
