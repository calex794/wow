//! Bounded application-side QUIC admission for the W6 authority.
//!
//! A permit is acquired BEFORE awaiting an unauthenticated TLS/QUIC
//! handshake. This bounds application tasks, concurrent handshakes and
//! authenticated RPC workers, but NOT UDP kernel queues or the underlying
//! noq/iroh packet parser before Endpoint::accept() yields. Internet
//! deployment still needs independent network-edge limits.
use crate::remote_anchor_w6::{RemoteAnchorLedger,serve_one_anchor_connection};
use iroh::endpoint::{Incoming,QuicTransportConfig,VarInt};
use std::{sync::{Arc,Mutex},time::{Duration,Instant}};
use tokio::sync::{OwnedSemaphorePermit,Semaphore};

const TOKEN_SCALE:u128=1_000_000_000;
const MAX_ACTIVE:usize=64;
const MAX_RATE:u32=256;
const MAX_BURST:u32=512;
const MAX_BUDGET:Duration=Duration::from_secs(10);

/// Must originate from protected configuration, not from a remote request.
#[derive(Clone,Copy,Debug)]
pub struct AnchorAdmissionPolicy {
    pub max_in_flight:usize,
    pub rate_per_second:u32,
    pub max_burst:u32,
    pub handshake_budget:Duration,
    pub connection_budget:Duration,
}
impl Default for AnchorAdmissionPolicy {
    fn default()->Self{
        Self {
            max_in_flight:16,
            rate_per_second:64,
            max_burst:64,
            handshake_budget:Duration::from_secs(2),
            connection_budget:Duration::from_secs(8),
        }
    }
}
impl AnchorAdmissionPolicy {
    fn valid(self)->bool{
        (1..=MAX_ACTIVE).contains(&self.max_in_flight)
            && (1..=MAX_RATE).contains(&self.rate_per_second)
            && (1..=MAX_BURST).contains(&self.max_burst)
            && self.handshake_budget>Duration::ZERO
            && self.handshake_budget<=MAX_BUDGET
            && self.connection_budget>Duration::ZERO
            && self.connection_budget<=MAX_BUDGET
    }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum AdmissionError { InvalidPolicy }

struct RateBucket {at:Instant,tokens:u128}
impl RateBucket {
    fn new(at:Instant,p:AnchorAdmissionPolicy)->Self{
        Self {at,tokens:u128::from(p.max_burst)*TOKEN_SCALE}
    }
    fn try_take(&mut self,now:Instant,p:AnchorAdmissionPolicy)->bool{
        let elapsed=now.saturating_duration_since(self.at);
        self.at=now;
        let refill=elapsed.as_nanos()
            .saturating_mul(u128::from(p.rate_per_second));
        self.tokens=self.tokens.saturating_add(refill)
            .min(u128::from(p.max_burst)*TOKEN_SCALE);
        if self.tokens<TOKEN_SCALE {return false;}
        self.tokens-=TOKEN_SCALE;
        true
    }
}

/// Exactly one instance must be shared by the entire authority endpoint.
/// Re-creating it per handshake would reset all quotas.
pub struct AnchorAdmission {
    policy:AnchorAdmissionPolicy,
    slots:Arc<Semaphore>,
    rate:Mutex<RateBucket>,
}
impl AnchorAdmission {
    pub fn new(policy:AnchorAdmissionPolicy)->Result<Self,AdmissionError>{
        if !policy.valid(){return Err(AdmissionError::InvalidPolicy);}
        Ok(Self {
            slots:Arc::new(Semaphore::new(policy.max_in_flight)),
            rate:Mutex::new(RateBucket::new(Instant::now(),policy)),
            policy,
        })
    }
    /// No queue or blocking waiters. Called before polling Incoming.
    pub fn try_admit(&self)->Option<OwnedSemaphorePermit>{
        let permit=Arc::clone(&self.slots).try_acquire_owned().ok()?;
        let mut budget=self.rate.lock().ok()?;
        if !budget.try_take(Instant::now(),self.policy){
            return None;
        }
        Some(permit)
    }
    pub fn available_slots(&self)->usize{self.slots.available_permits()}
    /// The permit covers TLS handshake, one request, response and ACK.
    /// QUIC Retry (address validation) is requested before any TLS work.
    /// Returns false for a rejected or retried incoming attempt; retried
    /// attempts must come back with a valid transport validation token.
    pub fn dispatch(
        &self,incoming:Incoming,service:Arc<Mutex<RemoteAnchorLedger>>,
    )->bool{
        let Some(permit)=self.try_admit() else {
            drop(incoming);
            return false;
        };
        if !incoming.remote_addr_validated() {
            // QUIC Retry is the fork's built-in stateless address
            // validation mechanism; no user-controlled IP-based session
            // state or heap allocation is introduced here. The retry
            // packet is sent BEFORE any application TLS worker is spawned.
            let _=incoming.retry();
            return false;
        }
        let policy=self.policy;
        tokio::spawn(async move {
            let _permit=permit;
            if let Ok(Ok(conn))=tokio::time::timeout(
                policy.handshake_budget,incoming,
            ).await {
                let _=tokio::time::timeout(
                    policy.connection_budget,
                    serve_one_anchor_connection(&conn,&service),
                ).await;
            }
        });
        true
    }
}

/// QUIC state-machine memory bounds configured BEFORE endpoint binding.
/// 1 bidirectional request-response stream and 1 unidirectional receipt;
/// each request is <=339 bytes. Connection-wide receive cap 8 KiB.
pub fn anchor_transport_config()->QuicTransportConfig{
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(1))
        .stream_receive_window(VarInt::from_u32(4096))
        .receive_window(VarInt::from_u32(8192))
        .send_window(8192)
        .max_idle_timeout(Some(
            Duration::from_secs(8).try_into()
                .expect("8 second QUIC timeout is encodable"),
        ))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_or_excessive_configurations(){
        let p=AnchorAdmissionPolicy::default();
        assert!(AnchorAdmission::new(p).is_ok());
        for bad in [
            AnchorAdmissionPolicy{max_in_flight:0,..p},
            AnchorAdmissionPolicy{max_in_flight:MAX_ACTIVE+1,..p},
            AnchorAdmissionPolicy{rate_per_second:0,..p},
            AnchorAdmissionPolicy{rate_per_second:MAX_RATE+1,..p},
            AnchorAdmissionPolicy{max_burst:0,..p},
            AnchorAdmissionPolicy{max_burst:MAX_BURST+1,..p},
            AnchorAdmissionPolicy{handshake_budget:Duration::ZERO,..p},
            AnchorAdmissionPolicy{handshake_budget:Duration::from_secs(11),..p},
            AnchorAdmissionPolicy{connection_budget:Duration::ZERO,..p},
            AnchorAdmissionPolicy{connection_budget:Duration::from_secs(11),..p},
        ] {
            assert!(matches!(
                AnchorAdmission::new(bad),Err(AdmissionError::InvalidPolicy)
            ));
        }
    }
    #[test]
    fn pre_handshake_slot_rejected_without_a_pending_queue(){
        let p=AnchorAdmissionPolicy{max_in_flight:2,..Default::default()};
        let guard=AnchorAdmission::new(p).unwrap();
        let a=guard.try_admit().unwrap();
        let b=guard.try_admit().unwrap();
        assert_eq!(guard.available_slots(),0);
        assert!(guard.try_admit().is_none());
        drop(a);
        assert_eq!(guard.available_slots(),1);
        assert!(guard.try_admit().is_some());
        drop(b);
        assert_eq!(guard.available_slots(),2);
    }
    #[test]
    fn token_budget_blocks_burst_and_refills_on_monotonic_clock(){
        let p=AnchorAdmissionPolicy {
            max_in_flight:4,rate_per_second:2,max_burst:2,
            ..Default::default()
        };
        let start=Instant::now();
        let mut b=RateBucket::new(start,p);
        assert!(b.try_take(start,p));
        assert!(b.try_take(start,p));
        assert!(!b.try_take(start,p));
        assert!(!b.try_take(start+Duration::from_millis(499),p));
        assert!(b.try_take(start+Duration::from_millis(500),p));
        assert!(!b.try_take(start+Duration::from_millis(500),p));
        assert!(b.try_take(start+Duration::from_secs(5),p));
        assert!(b.try_take(start+Duration::from_secs(5),p));
        assert!(!b.try_take(start+Duration::from_secs(5),p));
    }
    #[test]
    fn bounded_quic_transport_parameters_build(){
        let _=anchor_transport_config();
    }
}
