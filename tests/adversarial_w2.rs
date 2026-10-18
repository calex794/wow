use akula_wire_lab::{WireError,encode,Envelope,fragment};
use akula_wire_lab::transport::{FragmentPool,FragmentLimits,PeerKey,StreamDecoder,HARD_MAX_RESERVED_PARTS};
fn peer(i:u8)->PeerKey{PeerKey([i;16])}
fn payload(n:usize)->Vec<u8>{let e=Envelope{message_id:[1;16],route_token:[2;16],expires_at:17,priority:1,payload:vec![42;n]};encode(&e).unwrap()}
fn next(seed:&mut u64)->u64{*seed^=*seed<<13;*seed^=*seed>>7;*seed^=*seed<<17;*seed}
#[test] fn deterministic_fragment_chaos() {
 let mut seed=0x1234_5678_9abc_def0_u64;
 for trial in 0..400u32 {
  let src=payload((next(&mut seed)%900) as usize);
  let mtu=16+(next(&mut seed)%80) as usize;
  let frames=fragment(&src,trial+1,mtu).unwrap();
  let mut order:Vec<usize>=(0..frames.len()).collect();
  for i in (1..order.len()).rev(){let j=(next(&mut seed)%(i as u64+1)) as usize;order.swap(i,j);}
  let mut pool=FragmentPool::new(FragmentLimits::default()).unwrap();
  let mut complete=None;
  for (clock,index) in order.into_iter().enumerate(){
    let got=pool.accept(peer(1),clock as u64,&frames[index]).unwrap();
    if got.is_some(){complete=got;}
  }
  assert_eq!(complete,Some(src));
  assert_eq!(pool.stats().reserved_parts,0);
  assert_eq!(pool.accept(peer(1),1000,&frames[0]),Err(WireError::ReplaySuppressed));
 }
}
#[test] fn random_frames_never_exceed_quotas() {
 let mut seed=0x3141_5926_5358_9793u64;
 let mut pool=FragmentPool::new(FragmentLimits::default()).unwrap();
 for time in 0..20_000u64 {
   let length=(next(&mut seed)%550) as usize;
   let mut frame=vec![0;length];
   for b in &mut frame{*b=next(&mut seed) as u8;}
   let _=pool.accept(peer((next(&mut seed)%32) as u8),time,&frame);
   let stats=pool.stats();
   assert!(stats.reserved_parts<=HARD_MAX_RESERVED_PARTS);
   assert!(stats.buffered_bytes<=64*1024);
   assert!(stats.transfers<=16);
 }
 assert!(pool.expire(200_000).is_ok());
 assert_eq!(pool.stats().transfers,0);
}
#[test] fn partial_stream_and_bad_headers_do_not_grow_unbounded() {
 let mut d=StreamDecoder::new();let mut seed=0xabcde01234567890u64;
 for _ in 0..15_000 {
   let byte=next(&mut seed) as u8;
   let _=d.push(&[byte]);
   assert!(d.buffered_bytes()<=16*1024+4);
   if next(&mut seed)%13==0 {d.reset();}
 }
}
#[test] fn stale_replay_does_not_reserve_new_transfer() {
 let mut p=FragmentPool::new(FragmentLimits::default()).unwrap();
 let raw=payload(256);let frames=fragment(&raw,55,30).unwrap();
 for (n,f) in frames.iter().enumerate(){let _=p.accept(peer(4),n as u64,f).unwrap();}
 assert_eq!(p.stats().transfers,0);
 assert_eq!(p.accept(peer(4),1000,&frames[0]),Err(WireError::ReplaySuppressed));
 assert_eq!(p.stats().transfers,0);
 assert_eq!(p.expire(121_000),Ok(0));
 assert_eq!(p.accept(peer(4),121_001,&frames[0]),Ok(None));
}
