# bb8-ldap

`bb8-ldap` provides a [`bb8`](https://crates.io/crates/bb8) connection manager for [`ldap3`](https://crates.io/crates/ldap3) so that LDAP connections can be pooled and reused in asynchronous Rust applications. The manager handles creating new `ldap3::Ldap` connections and validating them before they are returned to the pool, making it easy to integrate LDAP authentication or directory lookups into services that already rely on `bb8`.

## Example

```rust
use bb8::Pool;
use bb8_ldap::LdapConnectionManager;
use ldap3::LdapConnSettings;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure the manager with the LDAP URL (StartTLS / LDAPS can be configured via LdapConnSettings).
    let manager = LdapConnectionManager::new_from_stringlike("ldap://localhost:1389")?
        .with_connection_settings(
            LdapConnSettings::new()
                .set_starttls(false) // customize as needed
        )
        .with_bind_credentials("cn=admin,dc=example,dc=org", "admin")
        .with_validation_timeout(std::time::Duration::from_secs(2));

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

## License

This project is licensed under the [MIT License](LICENSE-MIT).
