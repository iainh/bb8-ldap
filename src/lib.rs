pub use bb8;
pub use ldap3;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope};
use std::time::Duration;

#[derive(Clone)]
pub struct LdapConnectionManager {
    url: String,
    settings: LdapConnSettings,
}

impl LdapConnectionManager {
    /// Create a new `LdapConnectionManager`.
    pub fn new<S: Into<String>>(ldap_url: S) -> Self {
        LdapConnectionManager {
            url: ldap_url.into(),
            settings: LdapConnSettings::new(),
        }
    }

    pub fn with_connection_settings(mut self, settings: LdapConnSettings) -> Self {
        self.settings = settings;
        self
    }
}

impl bb8::ManageConnection for LdapConnectionManager {
    type Connection = ldap3::Ldap;
    type Error = ldap3::LdapError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let (conn, ldap) = LdapConnAsync::with_settings(self.settings.clone(), &self.url).await?;

        ldap3::drive!(conn);
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
        let conn_mgr = LdapConnectionManager::new(url);

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
