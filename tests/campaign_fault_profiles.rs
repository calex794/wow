//! Parallel-campaign adversarial checks on real W3/W8/W9/W10/W12/W13/W14
//! primitives. These are laboratory integrations on one machine, not a
//! Byzantine distributed-systems proof or a production STORE grant verifier.
use akula_wire_lab::{
    causal_w12::{CausalRequest,verify_w12_signed_claim},
    custody_transfer_w8::{self,OfferClaims},
    custody_witness_w9::{WitnessObservation,WitnessStore},
    joint_w14::{JointContext,JointEvidence,sign_joint_against_w10,verify_joint_against_w10},
    witness_pin_w10::WitnessPinStore,
    journal_w4::Journal,crypto_w3,crypto_identity_w3::SignedHeader,
    private_route_w3,trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
fn id(x:u8)->[u8;16]{[x;16]}
fn packet(sender:&SigningKey,recipient:&crypto_w3::RecipientPublic,msg:u8,body:&[u8])->Vec<u8>{
    private_route_w3::seal_private(sender,recipient,id(9),SignedHeader{
        sender_id:id(7),recipient_id:id(3),message_id:id(msg),expiry:10_000_000,epoch:1
    },body).unwrap()
}
fn req(msg:u8)->CausalRequest{
    CausalRequest{private_scope:id(5),custodian_id:id(8),custodian_epoch:1,
        recipient:id(3),message:id(msg),expiry_ms:10_000_000}
}
fn registry(custodian:&SigningKey,witness:Option<&SigningKey>)->TrustRegistry{
    let mut t=TrustRegistry::new();
    t.enroll(id(8),1,custodian.verifying_key()).unwrap();
    if let Some(w)=witness{t.enroll(id(17),9,w.verifying_key()).unwrap();}
    t
}
fn mix(mut x:u64)->u64{
    x=x.wrapping_add(0x9e3779b97f4a7c15);
    x=(x^(x>>30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x=(x^(x>>27)).wrapping_mul(0x94d049bb133111eb);
    x^(x>>31)
}
#[test]
fn w12_untrusted_key_bad_epoch_bad_packet_and_wrong_route_are_denied(){
    let dir=tempfile::tempdir().unwrap();
    let sender=SigningKey::from_bytes(&[7;32]);
    let custodian=SigningKey::from_bytes(&[8;32]);
    let attacker=SigningKey::from_bytes(&[55;32]);
    let mut t=registry(&custodian,None);
    let (_,recipient)=crypto_w3::new_recipient();
    let w3=packet(&sender,&recipient,4,b"opaque protected payload");
    let mut db=Journal::open(&dir.path().join("c.sqlite")).unwrap();
    assert!(db.enqueue_w3_with_causal(req(4),&w3,&attacker,&t).is_err());
    let mut wrong_epoch=req(4);wrong_epoch.custodian_epoch=2;
    assert!(db.enqueue_w3_with_causal(wrong_epoch,&w3,&custodian,&t).is_err());
    assert!(db.enqueue_w3_with_causal(req(7),&w3,&custodian,&t).is_err());
    assert!(db.enqueue_w3_with_causal(req(4),b"not W3",&custodian,&t).is_err());
    let mut invalid=req(4);invalid.private_scope=[0;16];
    assert!(db.enqueue_w3_with_causal(invalid,&w3,&custodian,&t).is_err());
    t.revoke(id(8)).unwrap();
    assert!(db.enqueue_w3_with_causal(req(4),&w3,&custodian,&t).is_err());
    assert!(db.audit_w12(id(5),id(8),&t).unwrap().is_none());
}
#[test]
fn w12_exact_ciphertext_idempotent_and_conflicting_encrypted_w3_rejected(){
    let dir=tempfile::tempdir().unwrap();
    let sender=SigningKey::from_bytes(&[7;32]);
    let custodian=SigningKey::from_bytes(&[8;32]);
    let t=registry(&custodian,None);
    let (_,recipient)=crypto_w3::new_recipient();
    let w3=packet(&sender,&recipient,4,b"original payload");
    let conflict=packet(&sender,&recipient,4,b"DIFFERENT protected payload");
    let mut db=Journal::open(&dir.path().join("c.sqlite")).unwrap();
    let head=db.enqueue_w3_with_causal(req(4),&w3,&custodian,&t).unwrap();
    assert_eq!(head.seq,1);
    assert_eq!(db.enqueue_w3_with_causal(req(4),&w3,&custodian,&t).unwrap(),head);
    assert!(db.enqueue_w3_with_causal(req(4),&conflict,&custodian,&t).is_err());
    assert_eq!(db.audit_w12(id(5),id(8),&t).unwrap(),Some(head));
    let x=db.export_w12_signed_head(id(5),id(8),&t).unwrap().unwrap();
    assert_eq!(verify_w12_signed_claim(&x,&t).unwrap().packet_digest,
        *blake3::hash(&w3).as_bytes());
    drop(db);
    let sqlite=rusqlite::Connection::open(dir.path().join("c.sqlite")).unwrap();
    for table in ["outbox","causal_w12_event","causal_w12_head"]{
        let sql=format!("SELECT COUNT(*) FROM {table}");
        let count:i64=sqlite.query_row(&sql,[],|r|r.get(0)).unwrap();
        assert_eq!(count,1,"{table}");
    }
    let n:i64=sqlite.query_row("SELECT COUNT(*) FROM receipt_outbox",[],|r|r.get(0)).unwrap();
    assert_eq!(n,0,"a custodian's W12 is NOT the recipient W4");
}
#[test]
fn w14_three_seeds_seven_attack_rates_no_wrong_joint_acceptance(){
    let dir=tempfile::tempdir().unwrap();
    let sender=SigningKey::from_bytes(&[7;32]);
    let custodian=SigningKey::from_bytes(&[8;32]);
    let witness=SigningKey::from_bytes(&[17;32]);
    let t=registry(&custodian,Some(&witness));
    let (_,recipient)=crypto_w3::new_recipient();
    let w3=packet(&sender,&recipient,4,b"lab private-letter content must not appear in W14");
    let mut db=Journal::open(&dir.path().join("custodian.sqlite")).unwrap();
    db.enqueue_w3_with_causal(req(4),&w3,&custodian,&t).unwrap();
    let head=db.export_w12_signed_head(id(5),id(8),&t).unwrap().unwrap();
    let signed=verify_w12_signed_claim(&head,&t).unwrap();
    let offer=custody_transfer_w8::sign_offer(OfferClaims{
        source_id:id(8),source_epoch:1,target_id:id(13),target_epoch:7,
        slot_alias:id(21),offer_id:id(31),
        ciphertext_digest:signed.packet_digest,expires_at_ms:500_000,
    },&custodian).unwrap();
    let mut w=WitnessStore::open(&dir.path().join("w9.sqlite"),id(17),9).unwrap();
    let cp=match w.observe(&offer,&witness,&t).unwrap(){
        WitnessObservation::FirstSeen(x)=>x,_=>panic!("unexpected fork")
    };
    let mut pin=WitnessPinStore::open(&dir.path().join("w10.sqlite"),id(17),9).unwrap();
    pin.pin(&cp,&t).unwrap();
    let evidence=JointEvidence{offer:&offer,checkpoint:&cp,w12:&head};
    let context=JointContext{private_scope:id(5),witness:id(17),epoch:9};
    let joint=sign_joint_against_w10(evidence,context,&witness,&t,&pin).unwrap();
    assert!(verify_joint_against_w10(&joint,evidence,context,&t,&pin).is_ok());
    assert!(!joint.windows(b"private-letter content".len())
        .any(|x|x==b"private-letter content"),"W14 cannot reveal W3 plaintext");
    let alternate_offer=custody_transfer_w8::sign_offer(OfferClaims{
        source_id:id(8),source_epoch:1,target_id:id(14),target_epoch:7,
        slot_alias:id(21),offer_id:id(41),
        ciphertext_digest:signed.packet_digest,expires_at_ms:500_000,
    },&custodian).unwrap();
    let mut injected=0usize;
    let mut honest=0usize;
    for seed in [21u64,71,107]{
        for pct in [1u64,5,10,20,40,70,90]{
            for index in 0..100u64{
                if mix(seed^mix(index)^0xBADu64)%100<pct {
                    injected+=1;
                    let method=(index+seed)%4;
                    let accepted=match method{
                        0=>{
                            let mut bytes=joint.clone();
                            let last=bytes.len()-1; bytes[last]^=1;
                            verify_joint_against_w10(&bytes,evidence,context,&t,&pin).is_ok()
                        },
                        1=>verify_joint_against_w10(&joint,
                            JointEvidence{offer:&alternate_offer,..evidence},context,&t,&pin).is_ok(),
                        2=>verify_joint_against_w10(&joint,evidence,
                            JointContext{private_scope:id(6),..context},&t,&pin).is_ok(),
                        _=>{
                            let mut cp_changed=cp.clone(); cp_changed[0]^=1;
                            verify_joint_against_w10(&joint,JointEvidence{checkpoint:&cp_changed,..evidence},
                                context,&t,&pin).is_ok()
                        }
                    };
                    assert!(!accepted,"corrupt or contradicting signature accepted");
                }else{
                    honest+=1;
                    assert!(verify_joint_against_w10(&joint,evidence,context,&t,&pin).is_ok());
                }
            }
        }
    }
    assert!(injected>0 && honest>0);
    println!("campaign_byzantine synthetic_adversarial_variants_rejected={injected} honest_accepts={honest}; not physical attackers");
    // These signatures are *claims*. They are NOT proof of continued storage.
}
