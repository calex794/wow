use akula_wire_lab::{decode, decode_extended, encode, encode_extended, Envelope, ExtendedEnvelope, Extension, WireError, MAX_EXTENSION_BYTES, MAX_EXTENSIONS, MAX_MESSAGE_BYTES};

fn sample() -> Envelope { Envelope { message_id: [3; 16], route_token: [5; 16], expires_at: 1792368000, priority: 1, payload: vec![0,255,13,10] } }
const BASE: &str = "a60000015003030303030303030303030303030303025005050505050505050505050505050505031a6ad55d800401054400ff0d0a";
const EXT: &str = "a70000015003030303030303030303030303030303025005050505050505050505050505050505031a6ad55d800401054400ff0d0a06a118184441424344";
fn hex(v: &str) -> Vec<u8> { (0..v.len()).step_by(2).map(|i| u8::from_str_radix(&v[i..i+2],16).unwrap()).collect() }
#[test] fn independent_fixed_vectors() {
    assert_eq!(encode(&sample()).unwrap(),hex(BASE));
    assert_eq!(decode(&hex(BASE)).unwrap(),sample());
    assert_eq!(decode_extended(&hex(BASE)).unwrap().envelope,sample());
    let v=ExtendedEnvelope { envelope: sample(), extensions: vec![Extension {id:24,value:b"ABCD".to_vec()}] };
    assert_eq!(encode_extended(&v).unwrap(),hex(EXT));
    assert_eq!(decode_extended(&hex(EXT)).unwrap(),v);
    assert_eq!(encode_extended(&decode_extended(&hex(EXT)).unwrap()).unwrap(),hex(EXT));
    assert!(decode(&hex(EXT)).is_err());
}
#[test] fn critical_unknown_fails_closed() {
    let mut v=hex(EXT); let pos=v.len()-6; v[pos]=25;
    assert_eq!(decode_extended(&v),Err(WireError::UnsupportedCriticalExtension));
    let v=ExtendedEnvelope {envelope:sample(),extensions:vec![Extension{id:25,value:vec![]}]};
    assert_eq!(encode_extended(&v),Err(WireError::UnsupportedCriticalExtension));
}
#[test] fn rejects_order_duplicates_and_nonminimal_keys() {
    let mut v=hex(EXT); let len=v.len(); v[len-8]=0xa2; v.extend_from_slice(&[0x18,0x18,0x40]);
    assert_eq!(decode_extended(&v),Err(WireError::InvalidEncoding));
    let mut v=hex(EXT); let len=v.len(); v[len-8]=0xa2; v.extend_from_slice(&[0x02,0x40]);
    assert_eq!(decode_extended(&v),Err(WireError::InvalidEncoding));
    let mut v=hex(EXT); let len=v.len(); v.splice(len-7..len-5,[0x19,0x00,0x18]);
    assert_eq!(decode_extended(&v),Err(WireError::InvalidEncoding));
}
#[test] fn rejects_empty_map_oversize_and_unknown_version() {
    let mut v=hex(BASE); v[0]=0xa7; v.extend_from_slice(&[6,0xa0]);
    assert_eq!(decode_extended(&v),Err(WireError::InvalidEncoding));
    let mut v=hex(BASE);v[2]=9;
    assert_eq!(decode_extended(&v),Err(WireError::UnsupportedVersion));
    assert_eq!(decode_extended(&vec![0;MAX_MESSAGE_BYTES+1]),Err(WireError::TooLarge));
    let x=ExtendedEnvelope{envelope:sample(),extensions:vec![Extension{id:2,value:vec![0;MAX_EXTENSION_BYTES+1]}]};
    assert_eq!(encode_extended(&x),Err(WireError::TooLarge));
    let x=ExtendedEnvelope{envelope:sample(),extensions:(1..=MAX_EXTENSIONS+1).map(|i|Extension{id:(i*2) as u16,value:vec![]}).collect()};
    assert_eq!(encode_extended(&x),Err(WireError::TooManyExtensions));
}
#[test] fn truncation_never_accepts_original() {
    let v=hex(EXT);
    for n in 0..v.len(){assert!(decode_extended(&v[..n]).is_err(),"prefix {n} accepted");}
    for i in 0..v.len(){
        let mut damaged=v.clone();damaged[i]^=1;
        assert_ne!(decode_extended(&damaged).ok(),decode_extended(&v).ok());
    }
}
