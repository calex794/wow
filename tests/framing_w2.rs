use akula_wire_lab::{encode,fragment,Envelope,WireError};
use akula_wire_lab::transport::{FragmentLimits,FragmentPool,PeerKey,StreamDecoder,HARD_MAX_PARTS_PER_TRANSFER};

fn bytes() -> Vec<u8> {
 let e=Envelope{message_id:[9;16],route_token:[1;16],expires_at:123,priority:1,payload:(0..200).map(|x|x as u8).collect()};
 encode(&e).unwrap()
}
fn peer(n:u8)->PeerKey{PeerKey([n;16])}
fn frame(id:u32,i:u16,count:u16,payload:&[u8])->Vec<u8>{
 let mut out=Vec::new();out.extend_from_slice(&id.to_be_bytes());out.extend_from_slice(&i.to_be_bytes());out.extend_from_slice(&count.to_be_bytes());out.extend_from_slice(payload);out
}
#[test] fn stream_one_byte_and_coalesced() {
 let payload=bytes();let framed=akula_wire_lab::stream_frame(&payload).unwrap();
 let mut decoder=StreamDecoder::new();
 for (i,b) in framed.iter().enumerate() {
  let (used,done)=decoder.push(&[*b]).unwrap();assert_eq!(used,1);
  assert_eq!(done.is_some(),i+1==framed.len());
  if let Some(complete)=done {assert_eq!(complete,payload);}
 }
 let joined=[framed.clone(),framed.clone()].concat();
 let mut decoder=StreamDecoder::new();let mut offset=0;let mut collected=vec![];
 while offset<joined.len(){
  let (used,frame)=decoder.push(&joined[offset..]).unwrap();assert!(used>0);offset+=used;
  if let Some(packet)=frame {collected.push(packet);}
 }
 assert_eq!(collected,vec![payload.clone(),payload]);
 assert_eq!(decoder.buffered_bytes(),0);
}
#[test] fn stream_bad_length_and_reset() {
 let mut d=StreamDecoder::new();
 assert_eq!(d.push(&[0xff,0xff,0xff,0xff]),Err(WireError::TooLarge));
 assert_eq!(d.buffered_bytes(),0);
 assert_eq!(d.push(&[0,0,0,0]),Err(WireError::InvalidEncoding));
 let f=akula_wire_lab::stream_frame(&bytes()).unwrap();
 let (used,packet)=d.push(&f).unwrap();assert_eq!(used,f.len());assert_eq!(packet,Some(bytes()));
}
#[test] fn fragments_out_of_order_peers_and_duplicates() {
 let source=bytes();let f=fragment(&source,123,35).unwrap();
 let mut p=FragmentPool::new(FragmentLimits::default()).unwrap();
 for (clock,i) in (0..f.len()).rev().enumerate() {
  let result=p.accept(peer(1),clock as u64,&f[i]).unwrap();
  if i>0 {assert!(result.is_none());}
  else {assert_eq!(result,Some(source.clone()));}
 }
 assert_eq!(p.stats().transfers,0);
 let _=p.accept(peer(1),1000,&f[0]).unwrap();
 assert_eq!(p.accept(peer(1),1001,&f[0]),Ok(None));
 let mut changed=f[0].clone();*changed.last_mut().unwrap()^=1;
 assert_eq!(p.accept(peer(1),1002,&changed),Err(WireError::ConflictingDuplicate));
 assert_eq!(p.stats().transfers,0);
}
#[test] fn same_transfer_id_across_peers_is_isolated() {
 let mut p=FragmentPool::new(FragmentLimits::default()).unwrap();
 assert_eq!(p.accept(peer(1),0,&frame(4,0,2,b"AA")),Ok(None));
 assert_eq!(p.accept(peer(2),1,&frame(4,0,2,b"BB")),Ok(None));
 assert_eq!(p.accept(peer(1),2,&frame(4,1,2,b"CC")),Ok(Some(b"AACC".to_vec())));
 assert_eq!(p.accept(peer(2),3,&frame(4,1,2,b"DD")),Ok(Some(b"BBDD".to_vec())));
}
#[test] fn budgets_limit_many_empty_allocations() {
 let mut p=FragmentPool::new(FragmentLimits::default()).unwrap();
 let f=frame(0,0,HARD_MAX_PARTS_PER_TRANSFER as u16 + 1,b"a");
 assert_eq!(p.accept(peer(1),0,&f),Err(WireError::FragmentCount));
 for i in 0..2u32 {assert_eq!(p.accept(peer(1),i as u64,&frame(i,0,100,b"x")),Ok(None));}
 assert_eq!(p.accept(peer(1),3,&frame(3,0,100,b"y")),Err(WireError::ResourceLimit));
 assert_eq!(p.stats().reserved_parts,200);
 let limits=FragmentLimits{max_reserved_parts:150,max_parts_per_transfer:100,..FragmentLimits::default()};
 let mut p=FragmentPool::new(limits).unwrap();
 assert_eq!(p.accept(peer(1),0,&frame(1,0,100,b"x")),Ok(None));
 assert_eq!(p.accept(peer(2),1,&frame(2,0,100,b"x")),Err(WireError::ResourceLimit));
}
#[test] fn idle_and_absolute_expiry_reclaim_parts() {
 let mut p=FragmentPool::new(FragmentLimits::default()).unwrap();
 assert_eq!(p.accept(peer(1),0,&frame(1,0,2,b"a")),Ok(None));
 assert_eq!(p.expire(29_999),Ok(0));
 assert_eq!(p.expire(30_000),Ok(1));
 assert_eq!(p.stats().reserved_parts,0);
 assert_eq!(p.expire(29_999),Err(WireError::NonMonotonicTime));
 assert_eq!(p.accept(peer(1),30_001,&frame(2,0,2,b"a")),Ok(None));
 assert_eq!(p.accept(peer(1),59_999,&frame(2,0,2,b"a")),Ok(None));
 assert_eq!(p.expire(60_001),Ok(1)); // duplicate does not extend idle timer
}
#[test] fn invalid_limits_or_inconsistent_fragment_fail_closed() {
 let limits=FragmentLimits{max_total_bytes:usize::MAX,..FragmentLimits::default()};
 assert!(matches!(FragmentPool::new(limits),Err(WireError::ResourceLimit)));
 let mut p=FragmentPool::new(FragmentLimits::default()).unwrap();
 assert_eq!(p.accept(peer(1),0,&frame(1,0,2,b"a")),Ok(None));
 assert_eq!(p.accept(peer(1),1,&frame(1,1,3,b"b")),Err(WireError::FragmentMismatch));
 assert_eq!(p.accept(peer(1),2,&frame(1,1,2,b"b")),Ok(Some(b"ab".to_vec())));
}
