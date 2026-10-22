//! W4 encrypted return travels via an intermediate QUIC/TLS relay that
//! has neither Alice's HPKE secret nor Bob's signing key. All endpoints bind
//! ONLY localhost on one CI runner, NOT physically independent machines.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal};
use akula_wire_lab::private_return_w4::{self, ReturnInvitation, ENVELOPE_LEN};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, endpoint::{Connection, presets}};
use rusqlite::{Connection as SqliteConnection, params};
use std::path::Path;
use std::time::Duration;
use tempfile::tempdir;

const ALPN: &[u8] = b"akula-wow/private-return-lab-only/1";
const WRITE_CAP: [u8;16] = [91;16];
const READ_CAP: [u8;16] = [92;16];
fn id(n:u8)->[u8;16]{[n;16]}
fn key(n:u8)->SigningKey { SigningKey::from_bytes(&[n;32]) }
async fn endpoint(alpns: Vec<Vec<u8>>) -> Endpoint {
    Endpoint::builder(presets::Minimal).clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap().alpns(alpns)
        .bind().await.unwrap()
}
async fn pair(server:&Endpoint, client:&Endpoint)->(Connection,Connection) {
    let (out, incoming)=tokio::join!(
        tokio::time::timeout(Duration::from_secs(10), client.connect(server.addr(),ALPN)),
        tokio::time::timeout(Duration::from_secs(10),async {
            server.accept().await.unwrap().await
        }),
    );
    (out.unwrap().unwrap(),incoming.unwrap().unwrap())
}
async fn exchange(connection:&Connection, request:&[u8])->Vec<u8> {
    let (mut tx,mut rx)=connection.open_bi().await.unwrap();
    tx.write_all(request).await.unwrap();
    tx.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(5),rx.read_to_end(ENVELOPE_LEN + 30))
        .await.unwrap().unwrap()
}
async fn relay_once(
    conn:&Connection,
    db:&Path,
    from_bob:iroh::EndpointId,
    to_alice:iroh::EndpointId,
) {
    let (mut tx, mut rx)=conn.accept_bi().await.unwrap();
    let request=rx.read_to_end(ENVELOPE_LEN+32).await.unwrap();
    let mut response=vec![0];
    if conn.remote_id()==from_bob && request.len()==17+ENVELOPE_LEN
        && request[0]==1 && request[1..17]==WRITE_CAP
    {
        let wire=&request[17..];
        let tag=private_return_w4::inspect_route(wire).unwrap();
        let db=SqliteConnection::open(db).unwrap();
        db.execute("INSERT INTO returns(tag,opaque) VALUES (?1,?2)
                    ON CONFLICT(tag) DO NOTHING",
                   params![tag.as_slice(),wire]).unwrap();
        response=vec![1];
    } else if conn.remote_id()==to_alice && request.len()==33
        && request[0]==2 && request[1..17]==READ_CAP
    {
        let db=SqliteConnection::open(db).unwrap();
        let found:Result<Vec<u8>,_>=db.query_row(
            "SELECT opaque FROM returns WHERE tag=?1",
            params![&request[17..33]],|row|row.get(0),
        );
        if let Ok(wire)=found {
            response=vec![2];
            response.extend_from_slice(&wire);
        }
    }
    tx.write_all(&response).await.unwrap();
    tx.finish().unwrap();
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn private_signed_w4_survives_untrusted_relay_quic_and_sqlite_without_leaking_ids() {
    let dir=tempdir().unwrap();
    let sender=endpoint(vec![]).await;
    let bob_endpoint=endpoint(vec![]).await;
    let outsider=endpoint(vec![]).await;
    let relay=endpoint(vec![ALPN.to_vec()]).await;
    assert_ne!(sender.id(),relay.id());

    let mut trust=TrustRegistry::new();
    trust.enroll(id(9),4,key(9).verifying_key()).unwrap();
    trust.enroll(id(8),6,key(8).verifying_key()).unwrap();
    let (bob_secret,bob_pub)=new_recipient();
    let (return_secret,return_pub)=new_recipient();
    let packet=private_route_w3::seal_private(
        &key(9),&bob_pub,id(4),SignedHeader {
            message_id:id(5), recipient_id:id(8), expiry:500_000,
            sender_id:id(9), epoch:4,
        }, b"real private W3 for actual reverse W4",
    ).unwrap();
    let mut inbox=Journal::open(&dir.path().join("bob.sqlite")).unwrap();
    let (insert, signed)=inbox.accept_private_authenticated_and_queue_receipt(
        &packet,TrustedRecipient {
            secret:&bob_secret,recipient_id:id(8),now:100_000,registry:&trust,
        },id(4),&key(8),6,
    ).unwrap();
    assert_eq!(insert,Insert::New);
    let opaque=private_return_w4::seal_signed_receipt(
        &signed,&return_pub,id(31),
    ).unwrap();
    assert_eq!(private_return_w4::inspect_route(&opaque).unwrap(),id(31));
    assert!(!opaque.windows(16).any(|x|x==id(5).as_slice() || x==id(8).as_slice()));
    assert!(!opaque.windows(signed.len()).any(|x|x==signed.as_slice()));
    let dbpath=dir.path().join("relayer.sqlite");
    let db=SqliteConnection::open(&dbpath).unwrap();
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
         CREATE TABLE returns(tag BLOB PRIMARY KEY, opaque BLOB NOT NULL);"
    ).unwrap();
    drop(db);

    // Bob -> relay over real TLS/QUIC, only opaque W4 stored on disk.
    let (out,inc)=pair(&relay,&bob_endpoint).await;
    assert_eq!(inc.remote_id(),bob_endpoint.id());
    let mut put=vec![1];
    put.extend_from_slice(&WRITE_CAP);
    put.extend_from_slice(&opaque);
    let (response,())=tokio::join!(
        exchange(&out,&put),
        relay_once(&inc,&dbpath,bob_endpoint.id(),sender.id()),
    );
    assert_eq!(response,vec![1]);
    drop(out);drop(inc);

    // A stolen return-route hint does not authorize a stranger to read W4.
    let (out,inc)=pair(&relay,&outsider).await;
    let mut get=vec![2];
    get.extend_from_slice(&READ_CAP);
    get.extend_from_slice(&id(31));
    let (denied,())=tokio::join!(
        exchange(&out,&get),
        relay_once(&inc,&dbpath,bob_endpoint.id(),sender.id()),
    );
    assert_eq!(denied,vec![0]);
    drop(out);drop(inc);

    // Replay-safe forward to Alice. The relay has never accessed plaintext.
    let (out,inc)=pair(&relay,&sender).await;
    let (returned,())=tokio::join!(
        exchange(&out,&get),
        relay_once(&inc,&dbpath,bob_endpoint.id(),sender.id()),
    );
    assert_eq!(returned[0],2);
    assert_eq!(&returned[1..],opaque.as_slice());
    let stored:Vec<u8>=SqliteConnection::open(&dbpath).unwrap().query_row(
        "SELECT opaque FROM returns WHERE tag=?1",
        params![id(31).as_slice()],|r|r.get(0),
    ).unwrap();
    assert_eq!(stored,opaque);
    let mut outbox=Journal::open(&dir.path().join("alice.sqlite")).unwrap();
    outbox.enqueue(id(8),id(5),500_000,&packet).unwrap();
    let invitation=ReturnInvitation {
        sender_secret:&return_secret,expected_tag:id(31),
        expires_at_ms:300_000,now_ms:100_000,recipient_trust:&trust,
    };
    assert_eq!(private_return_w4::open_verify_and_apply(
        &returned[1..],invitation,&mut outbox,
    ).unwrap(),Delivery::Recipient);
    assert_eq!(outbox.retry_bytes(id(8),id(5),101).unwrap(),None);
}
