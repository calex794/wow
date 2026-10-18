use akula_wire_lab::mailbox_w5::{Mailbox,MailboxLimits,MailError,PutStatus};
use tempfile::tempdir;
fn id(n:u8)->[u8;16]{[n;16]}
#[test] fn persistence_dedup_and_no_ttl_extension(){
 let d=tempdir().unwrap();let p=d.path().join("mail.sqlite");
 {let mut m=Mailbox::open(&p,MailboxLimits::default()).unwrap();
  assert_eq!(m.put(id(1),id(2),100,200,b"sealed").unwrap(),PutStatus::Stored);
  assert_eq!(m.put(id(1),id(2),101,200,b"sealed").unwrap(),PutStatus::Duplicate);
  assert!(matches!(m.put(id(1),id(2),101,201,b"sealed"),Err(MailError::Conflict)));
  assert!(matches!(m.put(id(1),id(2),101,200,b"other"),Err(MailError::Conflict)));
 }
 {let mut m=Mailbox::open(&p,MailboxLimits::default()).unwrap();
  assert_eq!(m.get_page(id(1),150,None,16).unwrap()[0].bytes,b"sealed");
  assert!(m.get_page(id(1),200,None,16).unwrap().is_empty());
  assert_eq!(m.purge_expired(200).unwrap(),1);
  assert_eq!(m.stats().unwrap().messages,0);
 }
}
#[test] fn token_quota_does_not_exhaust_others(){
 let d=tempdir().unwrap();let p=d.path().join("mail.sqlite");
 let limits=MailboxLimits{total_records:3,per_token_records:2,total_payload_bytes:100,
  per_token_payload_bytes:80,max_ttl_seconds:100};
 let mut m=Mailbox::open(&p,limits).unwrap();
 for n in [1,2] {m.put(id(1),id(n),0,50,b"token-one").unwrap();}
 assert!(matches!(m.put(id(1),id(3),0,50,b"excess"),Err(MailError::QuotaExceeded)));
 assert_eq!(m.put(id(2),id(1),0,50,b"other").unwrap(),PutStatus::Stored);
 assert!(matches!(m.put(id(3),id(1),0,50,b"out"),Err(MailError::QuotaExceeded)));
 assert_eq!(m.stats().unwrap().messages,3);
 assert_eq!(m.purge_expired(50).unwrap(),3);
 assert_eq!(m.put(id(3),id(1),50,60,b"again").unwrap(),PutStatus::Stored);
}
#[test] fn cursor_pagination_and_no_deletion_on_read(){
 let d=tempdir().unwrap();let p=d.path().join("mail.sqlite");
 let mut m=Mailbox::open(&p,MailboxLimits::default()).unwrap();
 for n in [9,1,4,2,3] {m.put(id(1),id(n),0,100,b"opaque").unwrap();}
 let a=m.get_page(id(1),1,None,2).unwrap();assert_eq!(a.iter().map(|r|r.id).collect::<Vec<_>>(),vec![id(1),id(2)]);
 let b=m.get_page(id(1),1,Some(a[1].id),2).unwrap();assert_eq!(b.iter().map(|r|r.id).collect::<Vec<_>>(),vec![id(3),id(4)]);
 let c=m.get_page(id(1),1,Some(b[1].id),2).unwrap();assert_eq!(c[0].id,id(9));
 assert_eq!(m.stats().unwrap().messages,5);
 assert!(matches!(m.get_page(id(1),1,None,17),Err(MailError::InvalidPage)));
}
#[test] fn bounds_and_stale_time(){
 let d=tempdir().unwrap();let p=d.path().join("mail.sqlite");
 let mut m=Mailbox::open(&p,MailboxLimits::default()).unwrap();
 assert!(matches!(m.put(id(1),id(1),0,86401,b"x"),Err(MailError::TooLongTtl)));
 assert!(matches!(m.put(id(1),id(1),-1,3,b"x"),Err(MailError::InvalidTime)));
 assert!(matches!(m.put(id(1),id(1),1,2,&vec![0;16385]),Err(MailError::InvalidPacket)));
 assert!(matches!(m.put(id(1),id(1),1,2,b""),Err(MailError::InvalidPacket)));
}
