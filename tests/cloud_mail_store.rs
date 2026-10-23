use akula_wire_lab::cloud_mail_store::{
    upload_and_pin, read_pinned, CloudError, CloudKey, CloudMailStore,
    CloudProvider, CloudRevision, ObjectHint, ReadPermit, UploadGrant,
};
use std::collections::HashMap;

fn key(n:u8)->CloudKey { CloudKey {namespace:[1;16], object:[n;16]} }
fn grant(k:CloudKey, bytes:&[u8])->UploadGrant {
    UploadGrant {key:k,expected_blake3:*blake3::hash(bytes).as_bytes(),
        exact_len:bytes.len(),max_bytes:1024,expires_at_ms:100}
}
fn permit(k:CloudKey)->ReadPermit {
    ReadPermit {key:k,max_bytes:1024,expires_at_ms:200}
}
struct Fake {
    entries:HashMap<CloudKey,(u64,Vec<u8>)>,
    uploads:usize,
    lost_ack:bool,
    missing_read:bool,
    corrupt_read:bool,
    dishonest_len:bool,
    unavailable:bool,
}
impl Default for Fake {
    fn default()->Self { Self {entries:HashMap::new(),uploads:0,lost_ack:false,
        missing_read:false,corrupt_read:false,dishonest_len:false,unavailable:false} }
}
impl CloudMailStore for Fake {
    fn provider(&self)->CloudProvider {CloudProvider::Fake}
    fn put_if_absent(&mut self,k:CloudKey,v:&[u8])->Result<(),CloudError>{
        self.uploads+=1;
        if self.entries.contains_key(&k) {return Err(CloudError::Conflict);}
        self.entries.insert(k,(1,v.to_vec()));
        if self.lost_ack {Err(CloudError::Ambiguous)} else {Ok(())}
    }
    fn describe(&self,k:CloudKey)->Result<ObjectHint,CloudError>{
        if self.unavailable {return Err(CloudError::Unavailable);}
        let (rev,b)=self.entries.get(&k).ok_or(CloudError::Missing)?;
        Ok(ObjectHint {revision:CloudRevision::Fake(*rev),
            reported_len:b.len()+usize::from(self.dishonest_len)})
    }
    fn get_exact(&self,k:CloudKey,rev:&CloudRevision,limit:usize)
        ->Result<Vec<u8>,CloudError>
    {
        if self.unavailable {return Err(CloudError::Unavailable);}
        if self.missing_read {return Err(CloudError::Missing);}
        let (actual,b)=self.entries.get(&k).ok_or(CloudError::Missing)?;
        if *rev!=CloudRevision::Fake(*actual) {return Err(CloudError::Missing);}
        if b.len()>limit {return Err(CloudError::TooLarge);}
        let mut value=b.clone();
        if self.corrupt_read {value[0]^=1;}
        Ok(value)
    }
}
#[test] fn exact_upload_then_receiver_read_without_custodian() {
    let mut f=Fake::default();
    let bytes=b"already encrypted W3 v3; never plaintext";
    let p=upload_and_pin(&mut f,grant(key(2),bytes),bytes,1).unwrap();
    assert_eq!(f.uploads,1);
    assert_eq!(read_pinned(&f,&p,permit(key(2)),2).unwrap(),bytes);
}
#[test] fn lost_ack_is_reconciled_without_repeat_put() {
    let mut f=Fake{lost_ack:true,..Default::default()};
    let data=b"ciphertext";
    let pin=upload_and_pin(&mut f,grant(key(2),data),data,1).unwrap();
    assert_eq!(pin.exact_len,data.len());
    assert_eq!(f.uploads,1);
}
#[test] fn loss_and_unavailability_are_not_false_success() {
    let mut f=Fake{lost_ack:true,unavailable:true,..Default::default()};
    assert_eq!(upload_and_pin(&mut f,grant(key(2),b"abcd"),b"abcd",1),
        Err(CloudError::Ambiguous));
}
#[test] fn mismatched_ciphertext_never_uploaded() {
    let mut f=Fake::default();
    assert_eq!(upload_and_pin(&mut f,grant(key(2),b"abcd"),b"abce",1),
        Err(CloudError::Corrupt));
    assert_eq!(f.uploads,0);
}
#[test] fn reject_expired_and_wrong_scope_before_network() {
    let mut f=Fake::default();
    let data=b"encrypted";
    assert_eq!(upload_and_pin(&mut f,grant(key(2),data),data,100),
        Err(CloudError::Expired));
    assert_eq!(f.uploads,0);
    let pin=upload_and_pin(&mut f,grant(key(2),data),data,1).unwrap();
    assert_eq!(read_pinned(&f,&pin,permit(key(3)),2),
        Err(CloudError::WrongScope));
}
#[test] fn tampered_or_missing_revision_is_rejected() {
    let mut f=Fake::default();
    let data=b"encrypted";
    let mut pin=upload_and_pin(&mut f,grant(key(2),data),data,1).unwrap();
    pin.revision=CloudRevision::Fake(999);
    assert_eq!(read_pinned(&f,&pin,permit(key(2)),2),Err(CloudError::Missing));
}
#[test] fn backend_corruption_rejected() {
    let mut f=Fake{corrupt_read:true,..Default::default()};
    assert_eq!(upload_and_pin(&mut f,grant(key(2),b"abcd"),b"abcd",1),
        Err(CloudError::Corrupt));
}
#[test] fn provider_metadata_lie_rejected() {
    let mut f=Fake{dishonest_len:true,..Default::default()};
    assert_eq!(upload_and_pin(&mut f,grant(key(2),b"abcd"),b"abcd",1),
        Err(CloudError::Corrupt));
}
#[test] fn missing_readback_not_success() {
    let mut f=Fake{missing_read:true,..Default::default()};
    assert_eq!(upload_and_pin(&mut f,grant(key(2),b"abcd"),b"abcd",1),
        Err(CloudError::Ambiguous));
}
#[test] fn create_only_prevents_overwrite() {
    let mut f=Fake::default();
    let data=b"abcdef";
    upload_and_pin(&mut f,grant(key(2),data),data,1).unwrap();
    assert_eq!(upload_and_pin(&mut f,grant(key(2),b"ghijkl"),b"ghijkl",2),
        Err(CloudError::Conflict));
    assert_eq!(f.entries.get(&key(2)).unwrap().1.as_slice(),data);
}
#[test] fn invalid_byte_limit_and_empty_packet_rejected() {
    let mut f=Fake::default();
    let mut g=grant(key(2),b"abcd");
    g.max_bytes=1;
    assert_eq!(upload_and_pin(&mut f,g,b"abcd",1),Err(CloudError::InvalidGrant));
    g.max_bytes=1024;
    g.exact_len=0;
    assert_eq!(upload_and_pin(&mut f,g,b"",1),Err(CloudError::InvalidGrant));
    assert_eq!(f.uploads,0);
}
#[test] fn repeated_reads_do_not_create_route_credits() {
    let mut f=Fake::default();
    let data=b"encrypted";
    let pin=upload_and_pin(&mut f,grant(key(2),data),data,1).unwrap();
    for _ in 0..3 {assert_eq!(read_pinned(&f,&pin,permit(key(2)),2).unwrap(),data);}
    assert_eq!(f.uploads,1);
}
