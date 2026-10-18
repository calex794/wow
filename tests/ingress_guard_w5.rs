use akula_wire_lab::ingress_guard_w5::{AdmissionError,IngressGuard,Lane};
fn id(i:u32)->[u8;16]{let mut b=[0u8;16];b[..4].copy_from_slice(&i.to_be_bytes());b}
#[test]
fn fake_id_rotation_does_not_reset_connection_attempt_budget(){
 let mut g=IngressGuard::new();let mut accepted=0;
 for i in 0..10_000{
  match g.begin(Lane::Iroh,id(i)){
   Ok(t)=>{accepted+=1;g.cancel(t).unwrap();}
   Err(AdmissionError::RateLimited)=>{},
   other=>panic!("unexpected: {other:?}"),
  }
 }
 assert_eq!(accepted,12);
 assert_eq!(g.stats().attempts_this_tick,12);
 g.advance_tick(1).unwrap();
 assert!(g.begin(Lane::Iroh,id(10_001)).is_ok());
 assert_eq!(g.advance_tick(0),Err(AdmissionError::ClockRollback));
}
#[test]
fn slow_handshake_slot_limits_and_timeouts(){
 let mut g=IngressGuard::new();
 let tickets:Vec<_>=(0..8).map(|i|g.begin(Lane::Iroh,id(i)).unwrap()).collect();
 assert_eq!(g.begin(Lane::Iroh,id(200)),Err(AdmissionError::AtCapacity));
 assert_eq!(g.active_on(Lane::Iroh),8);
 for t in &tickets {g.offer_fragment(*t,&[7;900]).unwrap();}
 assert_eq!(g.stats().buffered_bytes,7200);
 assert_eq!(g.offer_fragment(tickets[0],&[0;125]),Err(AdmissionError::TooLarge));
 g.advance_tick(10).unwrap();
 assert_eq!(g.stats().active,0);
 assert_eq!(g.stats().buffered_bytes,0);
 assert_eq!(g.offer_fragment(tickets[0],b"late"),Err(AdmissionError::InvalidTicket));
}
#[test]
fn untrusted_handshake_never_automatically_authenticates(){
 let mut g=IngressGuard::new();let t=g.begin(Lane::Bluetooth,id(2)).unwrap();
 g.offer_fragment(t,b"claimed-device-id=admin").unwrap();
 let bytes=g.take_untrusted(t).unwrap();
 assert_eq!(bytes.as_bytes(),b"claimed-device-id=admin");
 assert_eq!(g.stats().active,0);
 assert_eq!(g.stats().buffered_bytes,0);
 assert_eq!(g.cancel(t),Err(AdmissionError::InvalidTicket));
}
#[test]
fn cross_transport_global_buffer_limits_work_without_identity(){
 let mut g=IngressGuard::new();
 let mut tickets=Vec::new();
 for (n,lane) in [Lane::Bluetooth,Lane::LocalNetwork,Lane::Iroh,Lane::Gateway].into_iter().enumerate() {
  for i in 0..lane_limit(lane) {
   let t=g.begin(lane,id((n*10+i) as u32)).unwrap();
   tickets.push(t);
  }
 }
 assert_eq!(g.stats().active,24);
 for t in &tickets {
  g.offer_fragment(*t,&[2;512]).unwrap();
 }
 assert_eq!(g.stats().buffered_bytes,12288);
 assert_eq!(g.offer_fragment(tickets[0],&[5;513]),Err(AdmissionError::TooLarge));
 assert_eq!(g.stats().buffered_bytes,12288);
}
fn lane_limit(l:Lane)->usize { match l {Lane::Bluetooth=>4,_=>8} }
