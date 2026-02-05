#![deny(missing_docs, missing_debug_implementations)]

//! A [`bb8`] connection manager for [`ldap3`] LDAP connections.
//!
//! This crate provides [`LdapConnectionManager`], which implements [`bb8::ManageConnection`]
//! to pool and reuse asynchronous LDAP connections. The manager handles connection creation,
//! optional bind credentials, and health-check validation via lightweight LDAP searches.
//!
//! Both `bb8` and `ldap3` are re-exported for convenience, so you can use them directly
//! without adding separate dependencies.
//!
//! # Example
//!
//! ```no_run
//! use bb8::Pool;
//! use bb8_ldap::LdapConnectionManager;
//! use ldap3::LdapConnSettings;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let manager = LdapConnectionManager::new_from_stringlike("ldap://localhost:1389")?
//!         .with_connection_settings(LdapConnSettings::new().set_starttls(false))
//!         .with_bind_credentials("cn=admin,dc=example,dc=org", "admin")
//!         .with_connect_timeout(std::time::Duration::from_secs(3))
//!         .with_validation_timeout(std::time::Duration::from_secs(2));
//!
//!     let pool = Pool::builder().max_size(15).build(manager).await?;
//!
//!     let mut conn = pool.get().await?;
//!     let (results, _res) = conn
//!         .search("ou=users,dc=example,dc=org", ldap3::Scope::Subtree, "(cn=alice)", vec!["cn"])
//!         .await?
//!         .success()?;
//!
//!     println!("Found {} entries", results.len());
//!     Ok(())
//! }
//! ```
//!
//! # Feature Flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `tls-rustls-aws-lc-rs` | *(default)* Enable rustls with the aws-lc-rs crypto provider |
//! | `tls-rustls-ring` | Enable rustls with the ring crypto provider |
//! | `tls-native` | Enable native TLS support (use with `--no-default-features`) |
//!
//! Example using native TLS:
//!
//! ```toml
//! [dependencies]
//! bb8-ldap = { version = "*", default-features = false, features = ["tls-native"] }
//! ```
//!
//! # Supported URL Schemes
//!
//! This crate supports the following URL schemes:
//!
//! - `ldap://` — Standard LDAP over TCP (optionally upgraded with StartTLS)
//! - `ldapi://` — LDAP over Unix domain sockets
//!
//! Note: `ldaps://` (LDAP over implicit TLS) is **not** supported. To use TLS,
//! connect via `ldap://` and enable StartTLS with [`LdapConnSettings::set_starttls(true)`](ldap3::LdapConnSettings::set_starttls).
//!
//! # Connection Lifecycle
//!
//! Each connection is established using [`ldap3::LdapConnAsync`], which returns a
//! connection driver and an `Ldap` handle. The driver is spawned as a background
//! task via [`ldap3::drive!()`](ldap3::drive), and the `Ldap` handle is what gets
//! pooled and returned to callers. All LDAP operations go through this handle while
//! the background task manages the underlying protocol I/O.

/// Re-export the `bb8` crate for convenience.
pub use bb8;
/// Re-export the `ldap3` crate for convenience.
pub use ldap3;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope};
use std::fmt;
use std::time::Duration;
use url::Url;

/// A `bb8::ManageConnection` implementation for `ldap3` async connections.
#[derive(Clone)]
pub struct LdapConnectionManager {
    url: String,
    settings: LdapConnSettings,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    connect_timeout: Option<Duration>,
    validation_timeout: Duration,
    validation_base_dn: String,
    validation_filter: String,
    validation_scope: Scope,
    validation_attributes: Vec<String>,
}

impl fmt::Debug for LdapConnectionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapConnectionManager")
            .field("url", &self.url)
            .finish()
    }
}

impl LdapConnectionManager {
    /// Creates a new `LdapConnectionManager` with the given LDAP URL.
    ///
    /// The `ldap_url` is stored as-is without validation. Use [`new_from_stringlike`](Self::new_from_stringlike)
    /// if you need URL validation.
    pub fn new<S: Into<String>>(ldap_url: S) -> Self {
        LdapConnectionManager {
            url: ldap_url.into(),
            settings: LdapConnSettings::new(),
            bind_dn: None,
            bind_password: None,
            connect_timeout: None,
            validation_timeout: Duration::from_secs(1),
            validation_base_dn: String::new(),
            validation_filter: "(objectClass=*)".to_string(),
            validation_scope: Scope::Base,
            validation_attributes: vec!["1.1".to_string()],
        }
    }

    /// Creates a new `LdapConnectionManager` after validating the URL.
    ///
    /// The `ldap_url` is parsed and validated before creating the manager.
    /// Valid schemes are `ldap` and `ldapi`.
    ///
    /// Note: `ldaps://` is not accepted. To use TLS, pass an `ldap://` URL and configure
    /// StartTLS via [`LdapConnSettings::set_starttls(true)`](ldap3::LdapConnSettings::set_starttls).
    ///
    /// # Errors
    ///
    /// Returns [`LdapError::UrlParsing`](ldap3::LdapError::UrlParsing) if the URL is malformed.
    /// Returns [`LdapError::UnknownScheme`](ldap3::LdapError::UnknownScheme) if the scheme is not `ldap` or `ldapi`.
    pub fn new_from_stringlike<S: Into<String>>(ldap_url: S) -> Result<Self, ldap3::LdapError> {
        let url = ldap_url.into();
        let parsed = Url::parse(&url).map_err(ldap3::LdapError::from)?;

        match parsed.scheme() {
            "ldap" | "ldapi" => Ok(Self::new(url)),
            _ => Err(ldap3::LdapError::UnknownScheme(
                parsed.scheme().to_string(),
            )),
        }
    }

    /// Update the LDAP connection settings for this manager.
    pub fn with_connection_settings(mut self, settings: LdapConnSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Configures a simple bind to be performed when new connections are created.
    ///
    /// The `bind_dn` is the distinguished name to bind as (e.g., `"cn=admin,dc=example,dc=org"`).
    /// The `bind_password` is the password for the bind DN.
    ///
    /// The bind is performed immediately after each connection is established,
    /// before the connection is returned from the pool.
    pub fn with_bind_credentials<S: Into<String>>(mut self, bind_dn: S, bind_password: S) -> Self {
        self.bind_dn = Some(bind_dn.into());
        self.bind_password = Some(bind_password.into());
        self
    }

    /// Overrides the timeout used by `is_valid` health checks.
    ///
    /// The `timeout` specifies the maximum duration to wait for the validation search.
    /// The default is 1 second.
    pub fn with_validation_timeout(mut self, timeout: Duration) -> Self {
        self.validation_timeout = timeout;
        self
    }

    /// Overrides the validation search performed by `is_valid`.
    ///
    /// - `base_dn`: The base DN for the search. Default: `""` (root DSE).
    /// - `scope`: The search scope. Default: [`Scope::Base`].
    /// - `filter`: The search filter. Default: `"(objectClass=*)"`.
    /// - `attributes`: The attributes to return. Default: `["1.1"]` (no attributes).
    pub fn with_validation_search<S: Into<String>>(
        mut self,
        base_dn: S,
        scope: Scope,
        filter: S,
        attributes: Vec<S>,
    ) -> Self {
        self.validation_base_dn = base_dn.into();
        self.validation_scope = scope;
        self.validation_filter = filter.into();
        self.validation_attributes = attributes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets a timeout applied when establishing new connections.
    ///
    /// This timeout is applied during `connect()` on a clone of the configured
    /// `LdapConnSettings`, and overrides any timeout previously set on those settings.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }
}

/// Implements [`bb8::ManageConnection`] to provide connection pooling for `ldap3::Ldap` connections.
///
/// - `connect()` establishes a new LDAP connection and optionally performs a simple bind if credentials are configured.
/// - `is_valid()` validates a connection by performing a lightweight LDAP search with the configured timeout.
/// - `has_broken()` returns `true` if the underlying channel is closed (though this doesn't guarantee full bidirectional health).
impl bb8::ManageConnection for LdapConnectionManager {
    type Connection = ldap3::Ldap;
    type Error = ldap3::LdapError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let settings = match self.connect_timeout {
            Some(timeout) => self.settings.clone().set_conn_timeout(timeout),
            None => self.settings.clone(),
        };
        let (conn, ldap) = LdapConnAsync::with_settings(settings, &self.url).await?;

        ldap3::drive!(conn);
        let mut ldap = ldap;
        if let (Some(bind_dn), Some(bind_password)) = (&self.bind_dn, &self.bind_password) {
            ldap.simple_bind(bind_dn, bind_password).await?.success()?;
        }
        Ok(ldap)
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        // Touch the root DSE with a lightweight base-scope search that is commonly allowed even for anonymous binds.
        conn.with_timeout(self.validation_timeout)
            .search(
                &self.validation_base_dn,
                self.validation_scope,
                &self.validation_filter,
                self.validation_attributes.clone(),
            )
            .await?
            .success()?;
        Ok(())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        // Check whether the transmit channel is open. This doesn't mean that the bidirectional
        // communication is possible however
        conn.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bb8::ManageConnection;
    use testcontainers::{
        core::{client::ClientError, error::TestcontainersError},
        runners::AsyncRunner,
    };
    use testcontainers_modules::openldap::OpenLDAP;

    #[test]
    fn new_sets_default_settings() {
        let manager = LdapConnectionManager::new("ldap://example.com");
        assert_eq!(manager.url, "ldap://example.com");
        assert!(
            !manager.settings.starttls(),
            "starttls should be disabled by default"
        );
    }

    #[test]
    fn with_connection_settings_overrides_settings() {
        let manager = LdapConnectionManager::new("ldap://example.com");
        assert!(
            !manager.settings.starttls(),
            "control: default settings keep starttls disabled"
        );

        let updated_settings = LdapConnSettings::new().set_starttls(true);
        let updated_manager = manager.clone().with_connection_settings(updated_settings);

        assert_eq!(updated_manager.url, manager.url);
        assert!(
            updated_manager.settings.starttls(),
            "starttls should be enabled after overriding settings"
        );
    }

    #[test]
    fn with_connection_settings_leaves_original_untouched() {
        let manager = LdapConnectionManager::new("ldap://example.com");
        let updated_manager = manager.clone().with_connection_settings(
            LdapConnSettings::new().set_starttls(true),
        );

        assert!(
            !manager.settings.starttls(),
            "original manager should keep default settings"
        );
        assert!(
            updated_manager.settings.starttls(),
            "updated manager should reflect overrides"
        );
    }

    #[test]
    fn clone_preserves_custom_settings() {
        let manager = LdapConnectionManager::new("ldap://example.com")
            .with_connection_settings(LdapConnSettings::new().set_starttls(true));

        let cloned = manager.clone();

        assert_eq!(cloned.url, manager.url);
        assert!(
            cloned.settings.starttls(),
            "clone should maintain customized settings"
        );
    }

    #[test]
    fn new_accepts_owned_strings() {
        let url = "ldap://example.com".to_string();
        let manager = LdapConnectionManager::new(url);
        assert_eq!(manager.url, "ldap://example.com");
    }

    #[test]
    fn with_bind_credentials_sets_values() {
        let manager = LdapConnectionManager::new("ldap://example.com")
            .with_bind_credentials("cn=admin", "secret");

        assert_eq!(manager.bind_dn.as_deref(), Some("cn=admin"));
        assert_eq!(manager.bind_password.as_deref(), Some("secret"));
    }

    #[test]
    fn with_validation_timeout_updates_value() {
        let manager = LdapConnectionManager::new("ldap://example.com")
            .with_validation_timeout(Duration::from_secs(10));

        assert_eq!(manager.validation_timeout, Duration::from_secs(10));
    }

    #[test]
    fn with_validation_search_updates_values() {
        let manager = LdapConnectionManager::new("ldap://example.com").with_validation_search(
            "dc=example,dc=org",
            Scope::Subtree,
            "(cn=alice)",
            vec!["cn", "mail"],
        );

        assert_eq!(manager.validation_base_dn, "dc=example,dc=org");
        assert_eq!(manager.validation_scope, Scope::Subtree);
        assert_eq!(manager.validation_filter, "(cn=alice)");
        assert_eq!(manager.validation_attributes, vec!["cn", "mail"]);
    }

    #[test]
    fn with_connect_timeout_updates_settings() {
        let manager = LdapConnectionManager::new("ldap://example.com")
            .with_connect_timeout(Duration::from_secs(5));

        assert_eq!(manager.connect_timeout, Some(Duration::from_secs(5)));
    }

    #[test]
    fn new_from_stringlike_validates_urls() {
        let manager = LdapConnectionManager::new_from_stringlike("ldap://example.com")
            .expect("valid ldap URL should parse");
        assert_eq!(manager.url, "ldap://example.com");

        let err = LdapConnectionManager::new_from_stringlike("not a url")
            .expect_err("invalid URLs should be rejected");
        match err {
            ldap3::LdapError::UrlParsing { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let err = LdapConnectionManager::new_from_stringlike("http://example.com")
            .expect_err("unsupported schemes should be rejected");
        match err {
            ldap3::LdapError::UnknownScheme(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn connection_pool() -> anyhow::Result<()> {
        let node = match OpenLDAP::default()
            .with_user("test_user", "test_password")
            .start()
            .await
        {
            Ok(node) => node,
            Err(err @ TestcontainersError::Client(ClientError::PullImage { .. }))
            | Err(err @ TestcontainersError::Client(ClientError::Init(_))) => {
                eprintln!("skipping connection_pool test: {err}");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };

        let url = format!("ldap://127.0.0.1:{}", node.get_host_port_ipv4(1389).await?);
        let conn_mgr = LdapConnectionManager::new(url)
            .with_bind_credentials("cn=admin,dc=example,dc=org", "admin");

        let mut conn = conn_mgr.connect().await?;

        let search_res = conn
            .search(
                "ou=users,dc=example,dc=org",
                ldap3::Scope::Subtree,
                "(cn=*)",
                vec!["cn"],
            )
            .await;

        assert_eq!(search_res.iter().len(), 1);

        assert!(
            !conn_mgr.has_broken(&mut conn),
            "freshly connected session should be healthy"
        );

        conn.unbind().await?;
        assert!(
            conn_mgr.has_broken(&mut conn),
            "connection should be flagged as broken after unbind"
        );

        Ok(())
    }
}
