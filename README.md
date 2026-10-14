# bb8-ldap

`bb8-ldap` provides a [`bb8`](https://crates.io/crates/bb8) connection manager for [`ldap3`](https://crates.io/crates/ldap3) so that LDAP connections can be pooled and reused in asynchronous Rust applications. The manager handles creating new `ldap3::Ldap` connections and validating them before they are returned to the pool, making it easy to integrate LDAP authentication or directory lookups into services that already rely on `bb8`.

## Example

```rust
use bb8::Pool;
use bb8_ldap::LdapConnectionManager;
use ldap3::LdapConnSettings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure the manager with the LDAP URL (StartTLS can be configured via LdapConnSettings).
    let manager = LdapConnectionManager::new("ldap://localhost:1389")?
        .with_connection_settings(
            LdapConnSettings::new()
                .set_starttls(false) // customize as needed
        )
        .with_bind_credentials("cn=admin,dc=example,dc=org", "admin")
        .with_connect_timeout(std::time::Duration::from_secs(3))
        .with_validation_timeout(std::time::Duration::from_secs(2))
        .with_validation_search(
            "dc=example,dc=org",
            ldap3::Scope::Subtree,
            "(objectClass=*)",
            vec!["cn", "mail"],
        );

    // Build a pool with default settings.
    let pool = Pool::builder().max_size(15).build(manager).await?;

    // Fetch a connection from the pool and perform an LDAP search.
    let mut conn = pool.get().await?;
    let (results, _res) = conn
        .search(
            "ou=users,dc=example,dc=org",
            ldap3::Scope::Subtree,
            "(cn=alice)",
            vec!["cn", "mail"],
        )
        .await?
        .success()?;

    println!("Found {} entries", results.len());
    Ok(())
}
```

## Multiple endpoints and authentication safety

```rust
use bb8_ldap::{ldap3::LdapConnSettings, LdapConnectionManager};
use std::time::Duration;

fn manager() -> Result<LdapConnectionManager, bb8_ldap::ldap3::LdapError> {
    let manager = LdapConnectionManager::new_with_urls([
        "ldaps://ldap-a.example.org:636",
        "ldaps://ldap-b.example.org:636",
    ])?
        .with_connection_settings(LdapConnSettings::new())
        .with_bind_credentials("cn=service,dc=example,dc=org", "service-password")
        .with_connect_timeout(Duration::from_secs(3))
        .with_bind_timeout(Duration::from_secs(2));
    Ok(manager)
}
```

`new(url)` remains available. Both constructors accept `ldap`, `ldaps` and
`ldapi` URLs; LDAPS requires a TLS feature. Custom TLS settings are preserved.
Use StartTLS settings with `ldap://`, not `ldaps://`.

The first endpoint rotates for each connection attempt, including attempts from
manager clones. On connection establishment failures, each remaining endpoint is
tried once. The last error is returned if all fail. The connection timeout applies
per endpoint, not to the whole failover sequence. The optional bind timeout is
separate and defaults to no timeout. No bind errors (including invalid credentials
and timeouts), validation searches or caller operations are retried across servers.
bb8 may independently retry connection creation according to its pool settings.

**Never rebind pooled handles, including their clones, as users.** They share the
same LDAP session and authentication identity. Use service-bound pooled connections
for directory searches and separate, unpooled connections to verify user passwords.
The manager does not enforce this restriction on the re-exported LDAP handles.

## TLS features

- `tls-native`: Enable native TLS support in `ldap3` (use with `--no-default-features`).
- `tls-rustls-aws-lc-rs` (default): Enable rustls + aws-lc-rs provider in `ldap3`.
- `tls-rustls-ring`: Enable rustls + ring provider in `ldap3`.

## License

This project is licensed under the [MIT License](LICENSE-MIT).
