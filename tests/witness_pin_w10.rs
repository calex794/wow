//! W10 independent, durable checkpoint pinning without transport.
//! Test two different witness databases signing conflicting histories and
//! client-side fail-closed detection after gossip.
use akula_wire_lab::custody_transfer_w8::{self,OfferClaims};
use akula_wire_lab::custody_witness_w9::{
    self, ChainRelation, WitnessObservation, WitnessStore,
};
use akula_wire_lab::witness_pin_w10::{PinError,PinOutcome,WitnessPinStore};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

fn id(v:u8)->[u8;16]{[v;16]}
fn key(v:u8)->SigningKey{SigningKey::from_bytes(&[v;32])}
fn trust()->TrustRegistry{
    let mut t=TrustRegistry::new();
    t.enroll(id(21),3,key(21).verifying_key()).unwrap();
    t.enroll(id(17),9,key(17).verifying_key()).unwrap();
    t.enroll(id(18),10,key(18).verifying_key()).unwrap();
    t
}
fn offer(slot:u8,offer_id:u8,target:u8)->Vec<u8>{
    custody_transfer_w8::sign_offer(OfferClaims {
        source_id:id(21),source_epoch:3,
        target_id:id(target),target_epoch:if target==13{7}else{8},
        slot_alias:id(slot),offer_id:id(offer_id),
        ciphertext_digest:[7;32],expires_at_ms:500_000,
    },&key(21)).unwrap()
}
fn first(o:WitnessObservation)->Vec<u8>{
    match o {
        WitnessObservation::FirstSeen(cp)=>cp,
        WitnessObservation::Conflict(_)=>panic!("unexpected fork"),
    }
}
#[test]
fn pin_survives_restart_and_rejects_wrong_scope_or_epoch() {
    let dir=tempdir().unwrap();let trusted=trust();
    let witness_path=dir.path().join("w.sqlite");
    let pin_path=dir.path().join("pin.sqlite");
    let mut w=WitnessStore::open(&witness_path,id(17),9).unwrap();
    let cp=first(w.observe(&offer(41,31,13),&key(17),&trusted).unwrap());
    {
        let mut pin=WitnessPinStore::open(&pin_path,id(17),9).unwrap();
        assert_eq!(pin.pin(&cp,&trusted).unwrap(),PinOutcome::First);
        assert_eq!(pin.pin(&cp,&trusted).unwrap(),PinOutcome::Unchanged);
        assert_eq!(pin.inspect(&trusted).unwrap(),Some(1));
        assert!(!pin.frozen().unwrap());
    }
    let pin=WitnessPinStore::open(&pin_path,id(17),9).unwrap();
    assert_eq!(pin.current().unwrap(),Some(cp));
    assert!(matches!(WitnessPinStore::open(&pin_path,id(18),10),
        Err(PinError::WrongScope)));
}
#[test]
fn gaps_and_reverse_order_do_not_silently_replace_trusted_head() {
    let dir=tempdir().unwrap();let trusted=trust();
    let mut w=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let a=first(w.observe(&offer(41,31,13),&key(17),&trusted).unwrap());
    let b=first(w.observe(&offer(42,32,13),&key(17),&trusted).unwrap());
    let c=first(w.observe(&offer(43,33,13),&key(17),&trusted).unwrap());
    let mut pin=WitnessPinStore::open(&dir.path().join("p.sqlite"),id(17),9).unwrap();
    assert!(matches!(pin.pin(&c,&trusted),Err(PinError::MissingHistory)));
    assert!(pin.current().unwrap().is_none());
    assert_eq!(pin.pin(&a,&trusted).unwrap(),PinOutcome::First);
    assert!(matches!(pin.pin(&c,&trusted),Err(PinError::MissingHistory)));
    assert_eq!(pin.current().unwrap(),Some(a.clone()));
    assert_eq!(pin.pin(&b,&trusted).unwrap(),PinOutcome::Advanced);
    assert_eq!(pin.pin(&c,&trusted).unwrap(),PinOutcome::Advanced);
    assert!(matches!(pin.pin(&b,&trusted),Err(PinError::Stale)));
    assert_eq!(pin.inspect(&trusted).unwrap(),Some(3));
}
#[test]
fn split_view_witness_fork_evidence_persists_and_freezes_client() {
    let dir=tempdir().unwrap();let trusted=trust();
    let mut wa=WitnessStore::open(&dir.path().join("wa.sqlite"),id(17),9).unwrap();
    let mut wb=WitnessStore::open(&dir.path().join("wb.sqlite"),id(17),9).unwrap();
    let cp_a=first(wa.observe(&offer(41,31,13),&key(17),&trusted).unwrap());
    let cp_b=first(wb.observe(&offer(41,32,14),&key(17),&trusted).unwrap());
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &cp_a,&cp_b,id(17),&trusted,
    ).unwrap(),ChainRelation::Equivocation);
    let path=dir.path().join("pin.sqlite");
    {
        let mut client=WitnessPinStore::open(&path,id(17),9).unwrap();
        assert_eq!(client.pin(&cp_a,&trusted).unwrap(),PinOutcome::First);
        assert!(matches!(client.pin(&cp_b,&trusted),Err(PinError::Equivocation)));
        assert_eq!(client.fork().unwrap(),Some((cp_a.clone(),cp_b.clone())));
        assert!(client.frozen().unwrap());
    }
    let mut restored=WitnessPinStore::open(&path,id(17),9).unwrap();
    assert!(matches!(restored.pin(&cp_a,&trusted),Err(PinError::Frozen)));
    assert_eq!(restored.fork().unwrap(),Some((cp_a,cp_b)));
}
#[test]
fn untrusted_or_tampered_checkpoint_does_not_poison_pins() {
    let dir=tempdir().unwrap();let mut trusted=trust();
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let cp=first(witness.observe(&offer(41,31,13),&key(17),&trusted).unwrap());
    let mut altered=cp.clone();
    *altered.last_mut().unwrap()^=1;
    let mut pin=WitnessPinStore::open(&dir.path().join("p.sqlite"),id(17),9).unwrap();
    assert!(pin.pin(&altered,&trusted).is_err());
    assert!(pin.current().unwrap().is_none());
    trusted.revoke(id(17)).unwrap();
    assert!(pin.pin(&cp,&trusted).is_err());
    assert!(pin.current().unwrap().is_none());
}
