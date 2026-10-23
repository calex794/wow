#![cfg(feature = "causal-lab-fault")]
//! Child process SIGABRT before and after SQLite COMMIT, parent inspects
//! durable state. No physical power-cut/fsync guarantee or W4 is claimed.
use std::process::Command;
use std::path::Path;
use rusqlite::Connection;

fn spawn(path:&Path,mode:&str)->bool {
    Command::new(env!("CARGO_BIN_EXE_w12_causal_crash_worker"))
      .arg(path).arg(mode).output().unwrap().status.success()
}
fn count(path:&Path,table:&str)->i64{
    let db=Connection::open(path).unwrap();
    db.query_row(&format!("SELECT count(*) FROM {table}"),[],|r|r.get(0)).unwrap()
}
#[test]
fn before_commit_rolls_back_all_and_retry_restores_once(){
  let t=tempfile::tempdir().unwrap();
  let path=t.path().join("pre.sqlite");
  assert!(!spawn(&path,"before"));
  assert_eq!(count(&path,"outbox"),0);
  assert_eq!(count(&path,"causal_w12_event"),0);
  assert_eq!(count(&path,"causal_w12_head"),0);
  assert!(spawn(&path,"normal"));
  assert!(spawn(&path,"normal"));
  assert_eq!(count(&path,"outbox"),1);
  assert_eq!(count(&path,"causal_w12_event"),1);
  assert_eq!(count(&path,"causal_w12_head"),1);
  assert_eq!(count(&path,"receipt_outbox"),0);
}
#[test]
fn after_commit_keeps_exactly_one_record_on_recovery(){
  let t=tempfile::tempdir().unwrap();
  let path=t.path().join("post.sqlite");
  assert!(!spawn(&path,"after"));
  assert_eq!(count(&path,"outbox"),1);
  assert_eq!(count(&path,"causal_w12_event"),1);
  assert!(spawn(&path,"normal"));
  assert_eq!(count(&path,"outbox"),1);
  assert_eq!(count(&path,"causal_w12_event"),1);
  assert_eq!(count(&path,"receipt_outbox"),0);
}
