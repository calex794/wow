//! W14 private joint witness: cryptographically bind one W8 offer,
//! its W9 signed checkpoint and a W12 signed head for the same ciphertext.
//! This is observed evidence, NOT W4 or proof of ongoing physical storage.
//! No global broadcasting. W10 independent pinning remains a separate step.
use crate::{causal_w12::{verify_w12_signed_claim,VerifiedW12Claim},custody_transfer_w8::{self,OfferClaims},custody_witness_w9::{self,VerifiedCheckpoint},trust_w3::TrustRegistry};
use ed25519_dalek::{Signature,Signer,SigningKey,Verifier};
const DOMAIN:&[u8]=b"Akula/WOW/W14/JointPrivateWitness/Ed25519/v0\0";
pub const W14_LEN:usize=DOMAIN.len()+16+8+16+16+8+32+8+32+32+32+64;
#[derive(Debug)]
pub enum JointError {Invalid,Untrusted,WrongLink,BadSignature}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct JointClaim {
 pub witness:[u8;16],pub witness_epoch:u64,
 pub private_scope:[u8;16],pub custodian:[u8;16],
 pub w12_seq:u64,pub w12_digest:[u8;32],
 pub w9_seq:u64,pub w9_head:[u8;32],
 pub offer_hash:[u8;32],pub ciphertext_digest:[u8;32],
}
fn encode(c:JointClaim)->Vec<u8>{
 let mut b=DOMAIN.to_vec();
 b.extend_from_slice(&c.witness);
 b.extend_from_slice(&c.witness_epoch.to_be_bytes());
 b.extend_from_slice(&c.private_scope);
 b.extend_from_slice(&c.custodian);
 b.extend_from_slice(&c.w12_seq.to_be_bytes());
 b.extend_from_slice(&c.w12_digest);
 b.extend_from_slice(&c.w9_seq.to_be_bytes());
 b.extend_from_slice(&c.w9_head);
 b.extend_from_slice(&c.offer_hash);
 b.extend_from_slice(&c.ciphertext_digest);
 b
}
fn pair(
 offer:&[u8],checkpoint:&[u8],w12:&[u8],witness:[u8;16],
 trust:&TrustRegistry,
)->Result<(OfferClaims,VerifiedCheckpoint,VerifiedW12Claim),JointError>{
 let o=custody_transfer_w8::verify_offer(offer,trust).map_err(|_|JointError::Invalid)?;
 let cp=custody_witness_w9::verify_first_seen(offer,checkpoint,witness,trust).map_err(|_|JointError::Invalid)?;
 let w=verify_w12_signed_claim(w12,trust).map_err(|_|JointError::Invalid)?;
 // W8's *source* is required to be exactly the W12 storing custodian.
 // Checking W8's target instead would misattribute source custody.
 if w.custodian_id!=o.source_id || w.custodian_epoch!=o.source_epoch
    || w.packet_digest!=o.ciphertext_digest
 {return Err(JointError::WrongLink);}
 Ok((o,cp,w))
}
pub fn sign_joint(
 offer:&[u8],checkpoint:&[u8],w12:&[u8],private_scope:[u8;16],
 witness:[u8;16],epoch:u64,signer:&SigningKey,trust:&TrustRegistry,
)->Result<Vec<u8>,JointError>{
 if private_scope==[0;16]||epoch==0 || trust.key_for(witness,epoch).ok()!=Some(&signer.verifying_key()) {
   return Err(JointError::Untrusted)
 }
 let (_,cp,w)=pair(offer,checkpoint,w12,witness,trust)?;
 if w.private_scope!=private_scope||cp.witness_epoch!=epoch{return Err(JointError::WrongLink);}
 let claims=JointClaim{
  witness,witness_epoch:epoch,private_scope,custodian:w.custodian_id,
  w12_seq:w.seq,w12_digest:w.commitment.digest,w9_seq:cp.sequence,w9_head:cp.head,
  offer_hash:*blake3::hash(offer).as_bytes(),ciphertext_digest:w.packet_digest
 };
 let mut out=encode(claims);
 out.extend_from_slice(&signer.sign(&out).to_bytes());
 Ok(out)
}
pub fn verify_joint(
 joint:&[u8],offer:&[u8],checkpoint:&[u8],w12:&[u8],
 expected_scope:[u8;16],expected_witness:[u8;16],trust:&TrustRegistry,
)->Result<JointClaim,JointError>{
 if joint.len()!=W14_LEN||!joint.starts_with(DOMAIN){return Err(JointError::Invalid);}
 let mut offset=DOMAIN.len();
 let mut take=|n:usize|{let slice=&joint[offset..offset+n];offset+=n;slice};
 let witness:[u8;16]=take(16).try_into().map_err(|_|JointError::Invalid)?;
 let epoch=u64::from_be_bytes(take(8).try_into().map_err(|_|JointError::Invalid)?);
 let scope:[u8;16]=take(16).try_into().map_err(|_|JointError::Invalid)?;
 let custodian:[u8;16]=take(16).try_into().map_err(|_|JointError::Invalid)?;
 let seq=u64::from_be_bytes(take(8).try_into().map_err(|_|JointError::Invalid)?);
 let digest:[u8;32]=take(32).try_into().map_err(|_|JointError::Invalid)?;
 let w9_seq=u64::from_be_bytes(take(8).try_into().map_err(|_|JointError::Invalid)?);
 let w9_head:[u8;32]=take(32).try_into().map_err(|_|JointError::Invalid)?;
 let offer_hash:[u8;32]=take(32).try_into().map_err(|_|JointError::Invalid)?;
 let ciphertext_digest:[u8;32]=take(32).try_into().map_err(|_|JointError::Invalid)?;
 let c=JointClaim{witness,witness_epoch:epoch,private_scope:scope,custodian,w12_seq:seq,w12_digest:digest,w9_seq,w9_head,offer_hash,ciphertext_digest};
 if scope!=expected_scope||witness!=expected_witness||epoch==0{return Err(JointError::WrongLink);}
 let key=trust.key_for(witness,epoch).map_err(|_|JointError::Untrusted)?;
 let signature=Signature::from_slice(&joint[offset..]).map_err(|_|JointError::BadSignature)?;
 key.verify(&joint[..offset],&signature).map_err(|_|JointError::BadSignature)?;
 let (_,cp,w)=pair(offer,checkpoint,w12,witness,trust)?;
 if c.custodian!=w.custodian_id||c.w12_seq!=w.seq
 ||c.w12_digest!=w.commitment.digest||c.w9_seq!=cp.sequence
 ||c.w9_head!=cp.head||c.offer_hash!=*blake3::hash(offer).as_bytes()
 ||c.ciphertext_digest!=w.packet_digest||cp.witness_epoch!=epoch||w.private_scope!=scope
 {return Err(JointError::WrongLink);}
 Ok(c)
}


/// The actual W10 pinned W9 checkpoint MUST match the checkpoint
/// bound into W14. An in-memory W9 response alone is insufficient.
pub fn sign_joint_against_w10(
 offer:&[u8],checkpoint:&[u8],w12:&[u8],scope:[u8;16],
 witness:[u8;16],epoch:u64,signer:&SigningKey,trust:&TrustRegistry,
 pin:&crate::witness_pin_w10::WitnessPinStore,
)->Result<Vec<u8>,JointError>{
 let pinned=pin.current().map_err(|_|JointError::Invalid)?;
 if pinned.as_deref()!=Some(checkpoint){return Err(JointError::WrongLink);}
 pin.inspect(trust).map_err(|_|JointError::Invalid)?;
 sign_joint(offer,checkpoint,w12,scope,witness,epoch,signer,trust)
}
pub fn verify_joint_against_w10(
 joint:&[u8],offer:&[u8],checkpoint:&[u8],w12:&[u8],
 scope:[u8;16],witness:[u8;16],trust:&TrustRegistry,
 pin:&crate::witness_pin_w10::WitnessPinStore,
)->Result<JointClaim,JointError>{
 let pinned=pin.current().map_err(|_|JointError::Invalid)?;
 if pinned.as_deref()!=Some(checkpoint){return Err(JointError::WrongLink);}
 pin.inspect(trust).map_err(|_|JointError::Invalid)?;
 verify_joint(joint,offer,checkpoint,w12,scope,witness,trust)
}
