use akula_wire_lab::journal_w4::{Delivery,Journal,JournalError};
use rusqlite::Connection;
use tempfile::tempdir;
fn id(n:u8)->[u8;16]{[n;16]}
#[test] fn sqlite_trigger_abort_rolls_back_and_restart_is_clean(){
 let d=tempdir().unwrap();let path=d.path().join("fault.sqlite");
 {let mut journal=Journal::open(&path).unwrap();
  journal.enqueue(id(1),id(2),1000,b"encrypted").unwrap();
 }
 {let conn=Connection::open(&path).unwrap();
  conn.execute_batch("CREATE TRIGGER fail_status BEFORE UPDATE OF status ON outbox
    BEGIN SELECT RAISE(ABORT,'injected journal failure'); END;").unwrap();
 }
 {let mut journal=Journal::open(&path).unwrap();
  assert!(matches!(journal.record_verified_receipt(id(1),id(2),Delivery::Gateway),Err(JournalError::Db(_))));
  assert_eq!(journal.state(id(1),id(2)).unwrap(),Delivery::Queued);
 }
 {let conn=Connection::open(&path).unwrap();
  conn.execute_batch("DROP TRIGGER fail_status;").unwrap();
 }
 {let mut journal=Journal::open(&path).unwrap();
  assert_eq!(journal.retry_bytes(id(1),id(2),1).unwrap(),Some(b"encrypted".to_vec()));
  assert_eq!(journal.record_verified_receipt(id(1),id(2),Delivery::Gateway).unwrap(),Delivery::Gateway);
 }
}
