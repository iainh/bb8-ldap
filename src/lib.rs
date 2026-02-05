#![deny(missing_docs, missing_debug_implementations)]

//! bb8 connection manager for LDAP connections provided by `ldap3`.

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
}

impl fmt::Debug for LdapConnectionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapConnectionManager")
            .field("url", &self.url)
            .finish()
    }
}

impl LdapConnectionManager {
    /// Create a new `LdapConnectionManager`.
    pub fn new<S: Into<String>>(ldap_url: S) -> Self {
        LdapConnectionManager {
            url: ldap_url.into(),
            settings: LdapConnSettings::new(),
            bind_dn: None,
            bind_password: None,
        }
    }

    /// Create a new `LdapConnectionManager` after validating the URL.
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

    /// Configure a simple bind to be performed when new connections are created.
    pub fn with_bind_credentials<S: Into<String>>(mut self, bind_dn: S, bind_password: S) -> Self {
        self.bind_dn = Some(bind_dn.into());
        self.bind_password = Some(bind_password.into());
        self
    }
}

impl bb8::ManageConnection for LdapConnectionManager {
    type Connection = ldap3::Ldap;
    type Error = ldap3::LdapError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let (conn, ldap) = LdapConnAsync::with_settings(self.settings.clone(), &self.url).await?;

        ldap3::drive!(conn);
        let mut ldap = ldap;
        if let (Some(bind_dn), Some(bind_password)) = (&self.bind_dn, &self.bind_password) {
            ldap.simple_bind(bind_dn, bind_password).await?.success()?;
        }
        Ok(ldap)
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        // Touch the root DSE with a lightweight base-scope search that is allowed even for anonymous binds.
        conn.with_timeout(Duration::from_secs(1))
            .search("", Scope::Base, "(objectClass=*)", vec!["1.1"])
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
