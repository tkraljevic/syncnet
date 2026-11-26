//! Checks against the shared vectors in `vektori/vektori-zice.json`, which the Go
//! implementation produced. A vector is "this input gives exactly these bytes"; an
//! implementation that gets the same bytes speaks the same wire.
//!
//! Whatever Rust cannot produce today is named in `DIFFERENCES` with the reason, so a
//! gap is never skipped silently. The other vectors of that file are checked here or in
//! the module that owns the format; `CHECKED` says where.

#[cfg(test)]
mod tests {
    use crate::identity::{
        build_self_signed_cert_der, cert_cn_for_protocol, credential_uri_prefix,
        credential_urn_prefix, parse_public_key, public_key_to_base64, verify_peer_cert_der,
    };
    use crate::pairing::{SAS_NONCE_LEN, compute_sas_code, compute_sas_commit};
    use crate::tls::{alpn_proba, alpn_sig, alpn_web};
    use crate::transport::discovery::{Beacon, probe_text};
    use crate::transport::punch::{KIND_PUNCH, KIND_REPLY, PunchKeys};
    use crate::trust::SignedVersionEnvelope;
    use crate::wire::conversation::RefusalCode;
    use crate::wire::conversation_v1::EnvelopeV1;
    use crate::wire::frame::{DEFAULT_MAX_FRAME_LEN, read_frame, write_frame};
    use crate::wire::signal::{
        ReplayCache, SIGNAL_KIND_POZIV, SignalBody, SignalError, SignedSignalMessage,
        signal_signing_prefix, verify_signed_signal,
    };
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use ed25519_dalek::SigningKey;
    use serde_json::Value;
    use std::io::Cursor;

    /// Where each entry of `vektori-zice.json` is checked: here (a test of this module)
    /// or in the module that owns the format.
    const CHECKED: &[(&str, &str)] = &[
        ("ulaz", "keys_come_from_the_seeds"),
        ("certifikat", "certificate_name_and_credentials_uri"),
        (
            "vjerodajnice",
            "certificate_name_and_credentials_uri; trust::tests::gocop_wire_vectors_match_byte_for_byte",
        ),
        ("alpn", "alpn_and_discovery_texts"),
        ("pronalazenje", "alpn_and_discovery_texts"),
        (
            "uparivanje",
            "pairing_commitment_and_code; pairing::tests::pairing_wire_vectors_match_byte_for_byte",
        ),
        (
            "ovlast",
            "trust::tests::gocop_wire_vectors_match_byte_for_byte",
        ),
        (
            "clanstvoKljucemMreze",
            "trust::tests::gocop_wire_vectors_match_byte_for_byte",
        ),
        (
            "clanstvoOdPrimatelja",
            "trust::tests::gocop_wire_vectors_match_byte_for_byte",
        ),
        (
            "opoziv",
            "trust::tests::gocop_wire_vectors_match_byte_for_byte",
        ),
        (
            "oznakaOpoziva",
            "trust::tests::gocop_wire_vectors_match_byte_for_byte",
        ),
        ("omotnica", "envelope_and_refusal_codes"),
        (
            "odbijenica",
            "envelope_and_refusal_codes; wire::conversation_v1::tests::conversation_v1_vectors_match_byte_for_byte",
        ),
        ("kodoviOdbijanja", "envelope_and_refusal_codes"),
        ("signal.prefiksPotpisa", "signal_body_signature_and_frames"),
        ("signal.tijelo", "signal_body_signature_and_frames"),
        ("signal.potpis", "signal_body_signature_and_frames"),
        ("signal.najveciOkvir", "signal_body_signature_and_frames"),
        (
            "potpisVerzije",
            "wire::version_signature::tests::version_signature_vectors_match_byte_for_byte",
        ),
        ("udarciA", "punch_keys_and_packets_in_both_directions"),
        ("udarciB", "punch_keys_and_packets_in_both_directions"),
        (
            "posebniZnakovi",
            "trust::tests::gocop_special_chars_vectors_match_byte_for_byte; wire::conversation_v1::tests::conversation_v1_vectors_match_byte_for_byte",
        ),
    ];

    /// What the Rust implementation cannot produce today, by vector, with the reason.
    const DIFFERENCES: &[(&str, &str)] = &[
        (
            "signal.poruka",
            "Rust has no type for the outer signal message {vrsta, tijelo}. The signed part \
             inside it is produced and compared; the outer object is put together by the test.",
        ),
        (
            "signal.okvir",
            "Same outer message as signal.poruka. Only the 4-byte length framing is checked, \
             over the vector's own message.",
        ),
        (
            "signal.okvirPulsa",
            "Rust has no pulse message. Only the framing is checked, over the literal JSON.",
        ),
        (
            "mogucnosti",
            "Rust carries capability tags in its messages but has no list of its own tags; \
             the tags are to be reported by the application.",
        ),
        (
            "dogovorSCvoromBezOznaka",
            "Rust has no capability negotiation. It comes with the conversation logic.",
        ),
    ];

    /// The same two lists for `vektori-razgovora.json`.
    const CHECKED_CONVERSATION: &[(&str, &str)] = &[
        (
            "posiljatelj",
            "conversation_vectors_share_sender_and_credentials",
        ),
        (
            "vjerodajnice",
            "conversation_vectors_share_sender_and_credentials",
        ),
        ("frontier", CONVERSATION_TEST),
        ("frontierBezZnanja", CONVERSATION_TEST),
        ("granicaOdbijenih", CONVERSATION_TEST),
        ("rupe", CONVERSATION_TEST),
        ("delta", CONVERSATION_TEST),
        ("praznaDelta", CONVERSATION_TEST),
        ("zelje", CONVERSATION_TEST),
        ("sadrzaj", CONVERSATION_TEST),
        ("done", CONVERSATION_TEST),
        ("verzija", CONVERSATION_TEST),
        ("sadrzajSPosebnimZnakovima", CONVERSATION_TEST),
        ("deltaSPosebnimZnakovima", CONVERSATION_TEST),
        ("sadrzajBezKanala", CONVERSATION_TEST),
        (
            "deltaSPotpisom",
            "wire::version_signature::tests::signed_version_in_a_delta_keeps_its_signature_and_verifies",
        ),
    ];
    const CONVERSATION_TEST: &str =
        "wire::conversation_v1::tests::conversation_v1_vectors_match_byte_for_byte";

    const DIFFERENCES_CONVERSATION: &[(&str, &str)] = &[
        ("cop", "Rust has no package for transfer by file (.cop)."),
        (
            "primanje",
            "Rust has no admission at a distance (code, request and confirmation).",
        ),
    ];

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../../vektori/vektori-zice.json"))
            .expect("vektori-zice.json")
    }

    fn conversation_vectors() -> Value {
        serde_json::from_str(include_str!("../../../vektori/vektori-razgovora.json"))
            .expect("vektori-razgovora.json")
    }

    fn text<'a>(v: &'a Value, path: &[&str]) -> &'a str {
        path.iter()
            .fold(v, |v, key| &v[*key])
            .as_str()
            .unwrap_or_else(|| panic!("vector {} is not text", path.join(".")))
    }

    fn from_hex<const N: usize>(v: &Value, path: &[&str]) -> [u8; N] {
        hex::decode(text(v, path))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .unwrap_or_else(|| panic!("vector {} is not {N} bytes of hex", path.join(".")))
    }

    fn key(v: &Value, seed: &str) -> SigningKey {
        SigningKey::from_bytes(&from_hex(v, &["ulaz", seed]))
    }

    fn public(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }

    /// Fails for an entry of `v` that is in neither list, and for a listed entry that is
    /// gone from the file: a stale list is not coverage.
    fn assert_all_listed(v: &Value, checked: &[(&str, &str)], differences: &[(&str, &str)]) {
        let known = |path: &str| checked.iter().chain(differences).any(|(p, _)| *p == path);
        let mut unknown = Vec::new();
        for (top, value) in v.as_object().expect("vectors are an object") {
            if known(top) {
                continue;
            }
            // An entry that is not listed whole must have every part listed.
            match value.as_object() {
                Some(parts) => unknown.extend(
                    parts
                        .keys()
                        .map(|part| format!("{top}.{part}"))
                        .filter(|path| !known(path)),
                ),
                None => unknown.push(top.clone()),
            }
        }
        assert!(
            unknown.is_empty(),
            "vectors with no test and no named difference: {unknown:?}"
        );
        for (path, _) in checked.iter().chain(differences) {
            let found = path.split('.').try_fold(v, |v, key| v.get(key));
            assert!(found.is_some(), "{path} is listed but not in the vectors");
        }
    }

    #[test]
    fn every_vector_is_checked_or_named_as_a_difference() {
        assert_all_listed(&vectors(), CHECKED, DIFFERENCES);
        assert_all_listed(
            &conversation_vectors(),
            CHECKED_CONVERSATION,
            DIFFERENCES_CONVERSATION,
        );
    }

    #[test]
    fn conversation_vectors_share_sender_and_credentials() {
        let (v, c) = (vectors(), conversation_vectors());
        assert_eq!(text(&c, &["vjerodajnice"]), text(&v, &["vjerodajnice"]));
        let done: EnvelopeV1 = serde_json::from_str(text(&c, &["done"]).trim_end()).expect("done");
        assert_eq!(done.device_id.as_deref(), Some(text(&c, &["posiljatelj"])));
    }

    #[test]
    fn keys_come_from_the_seeds() {
        let v = vectors();
        for (seed, expected) in [
            ("sjemeA", "kljucA"),
            ("sjemeB", "kljucB"),
            ("sjemeMreze", "kljucMreze"),
        ] {
            let sk = key(&v, seed);
            let written = public_key_to_base64(&public(&sk));
            assert_eq!(written, text(&v, &["ulaz", expected]), "{seed}");
            assert_eq!(parse_public_key(&written).unwrap(), sk.verifying_key());
        }
    }

    #[test]
    fn certificate_name_and_credentials_uri() {
        let v = vectors();
        let protocol = text(&v, &["ulaz", "protokol"]);
        let credentials = text(&v, &["vjerodajnice"]).as_bytes();

        assert_eq!(
            cert_cn_for_protocol(protocol),
            text(&v, &["certifikat", "cn"])
        );
        assert_eq!(
            credential_uri_prefix(protocol),
            text(&v, &["ulaz", "oznakaVjerodajnica"])
        );
        assert_eq!(
            format!(
                "{}{}",
                credential_urn_prefix(protocol),
                URL_SAFE_NO_PAD.encode(credentials)
            ),
            text(&v, &["certifikat", "uriVjerodajnica"])
        );

        // The certificate carries those credentials and gives them back unchanged.
        let sk = key(&v, "sjemeA");
        let der = build_self_signed_cert_der(&sk, protocol, Some(credentials)).expect("cert");
        let verified = verify_peer_cert_der(&der, protocol).expect("verify");
        assert_eq!(verified.public_key, public(&sk));
        assert_eq!(verified.credentials.as_deref(), Some(credentials));
    }

    #[test]
    fn alpn_and_discovery_texts() {
        let v = vectors();
        let protocol = text(&v, &["ulaz", "protokol"]);

        assert_eq!(alpn_sig(protocol), text(&v, &["alpn", "signal"]).as_bytes());
        assert_eq!(alpn_web(protocol), text(&v, &["alpn", "web"]).as_bytes());
        assert_eq!(
            alpn_proba(protocol),
            text(&v, &["alpn", "proba"]).as_bytes()
        );

        assert_eq!(probe_text(protocol), text(&v, &["pronalazenje", "proba"]));
        let beacon_json = text(&v, &["pronalazenje", "beacon"]);
        let beacon: Beacon = serde_json::from_str(beacon_json).expect("beacon");
        assert_eq!(beacon.protocol, protocol);
        assert_eq!(serde_json::to_string(&beacon).unwrap(), beacon_json);
    }

    #[test]
    fn pairing_commitment_and_code() {
        let v = vectors();
        let protocol = text(&v, &["ulaz", "protokol"]);
        let caller: [u8; SAS_NONCE_LEN] = from_hex(&v, &["ulaz", "brojPozivatelja"]);
        let listener: [u8; SAS_NONCE_LEN] = from_hex(&v, &["ulaz", "brojSlusalice"]);

        let commit = compute_sas_commit(protocol, &caller);
        assert_eq!(hex::encode(commit), text(&v, &["uparivanje", "obveza"]));
        assert_eq!(
            format!(r#"{{"obveza":"{}"}}"#, STANDARD.encode(commit)),
            text(&v, &["uparivanje", "porukaObveze"])
        );
        assert_eq!(
            format!(r#"{{"broj":"{}"}}"#, STANDARD.encode(listener)),
            text(&v, &["uparivanje", "porukaBroja"])
        );
        assert_eq!(
            compute_sas_code(
                protocol,
                &public(&key(&v, "sjemeA")),
                &public(&key(&v, "sjemeB")),
                &caller,
                &listener,
            ),
            text(&v, &["uparivanje", "kod"])
        );
    }

    #[test]
    fn envelope_and_refusal_codes() {
        let v = vectors();
        for name in ["omotnica", "odbijenica"] {
            let line = text(&v, &[name]);
            let json = line.strip_suffix('\n').expect("a line ends with a newline");
            let envelope: EnvelopeV1 = serde_json::from_str(json).expect(name);
            assert_eq!(serde_json::to_string(&envelope).unwrap(), json, "{name}");
        }

        let codes = &v["kodoviOdbijanja"];
        for (name, code) in [
            ("opce", RefusalCode::General),
            ("nepoznat-kanal", RefusalCode::UnknownChannel),
            ("zauzet", RefusalCode::Busy),
            ("odbijeno", RefusalCode::Refused),
            ("nije-clan", RefusalCode::NotAMember),
            ("upis-zauzet", RefusalCode::WriteBusy),
            ("bez-tailscalea", RefusalCode::NoTailscale),
        ] {
            assert_eq!(codes[name].as_u64(), Some(code.as_u64()), "{name}");
        }
        assert_eq!(
            codes.as_object().unwrap().len(),
            7,
            "a refusal code was added to the vectors"
        );
    }

    fn vector_signal_body(v: &Value) -> SignalBody {
        SignalBody {
            ver: 1,
            sesija: text(v, &["ulaz", "sesija"]).to_owned(),
            od: String::new(),
            za: text(v, &["ulaz", "kljucB"]).to_owned(),
            sastajaliste: text(v, &["ulaz", "kljucMreze"]).to_owned(),
            izdano: v["ulaz"]["vrijeme"].as_i64().expect("vrijeme"),
            tajna: None,
            kandidati: vec![],
            nat: None,
            odluka: None,
            razlog: None,
            obrada_ms: None,
            pokusaj: None,
            rtt_ms: None,
            vj: None,
        }
    }

    #[test]
    fn signal_body_signature_and_frames() {
        let v = vectors();
        let protocol = text(&v, &["ulaz", "protokol"]);
        let (sk_a, sk_b, sk_net) = (key(&v, "sjemeA"), key(&v, "sjemeB"), key(&v, "sjemeMreze"));

        assert_eq!(
            signal_signing_prefix(protocol, SIGNAL_KIND_POZIV),
            text(&v, &["signal", "prefiksPotpisa"]).as_bytes()
        );

        let msg =
            SignedSignalMessage::sign(&sk_a, protocol, SIGNAL_KIND_POZIV, vector_signal_body(&v));
        assert_eq!(
            String::from_utf8(msg.tijelo.clone()).unwrap(),
            text(&v, &["signal", "tijelo"])
        );
        assert_eq!(
            STANDARD.encode(&msg.potpis),
            text(&v, &["signal", "potpis"])
        );

        let body = verify_signed_signal(
            protocol,
            &msg,
            &sk_b.verifying_key(),
            &sk_net.verifying_key(),
            v["ulaz"]["vrijeme"].as_i64().unwrap() + 10,
            &mut ReplayCache::default(),
            |sender, _| sender == &sk_a.verifying_key(),
        )
        .expect("the vector's signal verifies");
        assert_eq!(body.sesija, text(&v, &["ulaz", "sesija"]));

        // DIFFERENCES: the outer message is the test's, the signed part inside it is Rust's.
        let message = format!(
            r#"{{"vrsta":"{SIGNAL_KIND_POZIV}","tijelo":{}}}"#,
            serde_json::to_string(&msg).unwrap()
        );
        assert_eq!(message, text(&v, &["signal", "poruka"]));

        assert_eq!(
            v["signal"]["najveciOkvir"].as_u64(),
            Some(DEFAULT_MAX_FRAME_LEN as u64)
        );
        for (payload, vector) in [
            (message.as_bytes(), "okvir"),
            (
                br#"{"vrsta":"puls","tijelo":{"odgovori":true}}"#.as_slice(),
                "okvirPulsa",
            ),
        ] {
            let mut framed = Vec::new();
            write_frame(&mut framed, payload, DEFAULT_MAX_FRAME_LEN).unwrap();
            assert_eq!(
                hex::encode(&framed),
                text(&v, &["signal", vector]),
                "{vector}"
            );
            assert_eq!(
                read_frame(&mut Cursor::new(framed), DEFAULT_MAX_FRAME_LEN).unwrap(),
                payload
            );
        }
    }

    #[test]
    fn signed_extreme_signal_timestamp_is_rejected_without_overflow() {
        let v = vectors();
        let protocol = text(&v, &["ulaz", "protokol"]);
        let mut body = vector_signal_body(&v);
        body.izdano = i64::MIN;
        let msg = SignedSignalMessage::sign(&key(&v, "sjemeA"), protocol, SIGNAL_KIND_POZIV, body);
        assert_eq!(
            verify_signed_signal(
                protocol,
                &msg,
                &key(&v, "sjemeB").verifying_key(),
                &key(&v, "sjemeMreze").verifying_key(),
                i64::MAX,
                &mut ReplayCache::default(),
                |_, _| true
            ),
            Err(SignalError::ClockSkew)
        );
    }

    #[test]
    fn punch_keys_and_packets_in_both_directions() {
        let v = vectors();
        let protocol = text(&v, &["ulaz", "protokol"]);
        let session = text(&v, &["ulaz", "sesija"]);
        let call: [u8; 32] = from_hex(&v, &["ulaz", "tajnaPoziva"]);
        let response: [u8; 32] = from_hex(&v, &["ulaz", "tajnaOdziva"]);
        let (a, b) = (public(&key(&v, "sjemeA")), public(&key(&v, "sjemeB")));

        for (side, mine, theirs) in [("udarciA", &a, &b), ("udarciB", &b, &a)] {
            let keys = PunchKeys::derive(protocol, session, &call, &response, mine, theirs)
                .expect("derive");
            assert_eq!(
                Some(u64::from(keys.dir)),
                v[side]["smjer"].as_u64(),
                "{side}"
            );
            assert_eq!(
                hex::encode(keys.send_key),
                text(&v, &[side, "kljucSlanja"]),
                "{side}"
            );
            assert_eq!(
                hex::encode(keys.build_packet(KIND_PUNCH, 7)),
                text(&v, &[side, "udarac7"]),
                "{side}"
            );
            assert_eq!(
                hex::encode(keys.build_packet(KIND_REPLY, 7)),
                text(&v, &[side, "odgovor7"]),
                "{side}"
            );
        }
    }

    /// `SignedVersionEnvelope` is an older shape of the Rust implementation only
    /// (`<protocol>-ver-v1|[...]`); the shared vectors have no entry for it, so the expected
    /// bytes here only pin it against accidental change. The shape both implementations
    /// share is in `wire::version_signature` and is checked against the vectors there.
    #[test]
    fn version_signature_binds_all_version_fields() {
        const KEY_A: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";
        let seed = SigningKey::from_bytes(&[0x01; 32]);
        let v = SignedVersionEnvelope {
            version_id: "0199c82c-0000-7000-8000-000000000001".into(),
            entity: "shopping_lists".into(),
            entity_id: "list-1".into(),
            node_id: KEY_A.into(),
            supersedes: String::new(),
            archived: false,
            channel: "list:list-1".into(),
            created_at: "2025-10-09T08:53:20Z".into(),
            created_at_unix: 1760000000,
            schema_version: 1,
            author_pub_key: KEY_A.into(),
            grant_ref: "grant-1".into(),
            payload: r#"{"name":"Subota"}"#.into(),
            signature: "+SiCX03oxCKskTFykV1Xt2QcprHLYYRhrmvU0LdvBA8yPwVTG0I9ONbN6h2LsW9sOqyFU1rwVQzfK9GwWUyGBA==".into(),
        };
        assert_eq!(
            std::str::from_utf8(&v.canonical_signing_bytes("list2cart")).unwrap(),
            r#"list2cart-ver-v1|[1,"shopping_lists","list-1","0199c82c-0000-7000-8000-000000000001","iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","",false,"list:list-1","2025-10-09T08:53:20Z",1760000000,"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=","grant-1","{\"name\":\"Subota\"}"]"#
        );
        v.verify_signature("list2cart").expect("verify");
        assert_eq!(v.clone().sign("list2cart", &seed).signature, v.signature);
    }
}
