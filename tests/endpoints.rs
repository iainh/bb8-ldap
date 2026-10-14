use bb8_ldap::{bb8::ManageConnection, ldap3::LdapError, LdapConnectionManager};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

// Minimal LDAP peer: read short BER messages and return bind/search results.
async fn peer(code: Option<u8>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ldap://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        loop {
            let mut header = [0; 2];
            if stream.read_exact(&mut header).await.is_err() {
                break;
            }
            assert_eq!(header[0], 0x30);
            assert!(header[1] < 128);
            let mut body = vec![0; header[1] as usize];
            stream.read_exact(&mut body).await.unwrap();
            let id = body[2];
            let tag = body[3];
            if tag == 0x42 {
                break;
            }
            let Some(code) = code else {
                std::future::pending::<()>().await;
                unreachable!();
            };
            let response_tag = match tag {
                0x60 => 0x61,
                0x63 => 0x65,
                _ => panic!("unexpected operation"),
            };
            stream
                .write_all(&[
                    0x30,
                    0x0c,
                    0x02,
                    0x01,
                    id,
                    response_tag,
                    0x07,
                    0x0a,
                    0x01,
                    code,
                    0x04,
                    0,
                    0x04,
                    0,
                ])
                .await
                .unwrap();
        }
    });
    (url, task)
}

#[test]
fn constructors_validate_every_endpoint() {
    for scheme in ["ldap", "ldaps", "ldapi"] {
        assert!(LdapConnectionManager::new(format!("{scheme}://localhost")).is_ok());
    }
    assert!(LdapConnectionManager::new_with_urls(Vec::<String>::new()).is_err());
    assert!(LdapConnectionManager::new_with_urls(["ldap://localhost", "not a url"]).is_err());
    assert!(
        LdapConnectionManager::new_with_urls(["ldap://localhost", "https://localhost"]).is_err()
    );
    let debug = format!(
        "{:?}",
        LdapConnectionManager::new("ldap://secret:password@localhost")
            .unwrap()
            .with_bind_credentials("secret", "password")
    );
    assert!(!debug.contains("secret") && !debug.contains("password"));
}

#[tokio::test]
async fn failover_binds_and_validates() {
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_url = format!("ldap://{}", dead.local_addr().unwrap());
    drop(dead);
    let (url, task) = peer(Some(0)).await;
    let manager = LdapConnectionManager::new_with_urls([dead_url, url])
        .unwrap()
        .with_connect_timeout(Duration::from_millis(200))
        .with_bind_timeout(Duration::from_millis(200))
        .with_bind_credentials("cn=service", "password");
    let mut conn = manager.connect().await.unwrap();
    manager.is_valid(&mut conn).await.unwrap();
    conn.unbind().await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn clones_rotate_first_endpoint() {
    let (a, task_a) = peer(Some(0)).await;
    let (b, task_b) = peer(Some(0)).await;
    let manager = LdapConnectionManager::new_with_urls([a, b]).unwrap();
    let mut first = manager.connect().await.unwrap();
    let mut second = manager.clone().connect().await.unwrap();
    first.unbind().await.unwrap();
    second.unbind().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        task_a.await.unwrap();
        task_b.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bind_errors_never_fail_over() {
    for code in [Some(49), None] {
        let (url, task) = peer(code).await;
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let manager = LdapConnectionManager::new_with_urls([
            url,
            format!("ldap://{}", unused.local_addr().unwrap()),
        ])
        .unwrap()
        .with_connect_timeout(Duration::from_secs(5))
        .with_bind_timeout(Duration::from_millis(50))
        .with_bind_credentials("cn=service", "password");
        let error = tokio::time::timeout(Duration::from_secs(1), manager.connect())
            .await
            .unwrap()
            .unwrap_err();
        match code {
            None => assert!(matches!(error, LdapError::Timeout { .. })),
            Some(_) => {
                assert!(matches!(error, LdapError::LdapResult { ref result } if result.rc == 49))
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), unused.accept())
                .await
                .is_err()
        );
        task.abort();
    }
}
