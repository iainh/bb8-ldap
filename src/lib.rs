pub use bb8;
pub use ldap3;

use async_trait::async_trait;
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
#[async_trait]
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

        Ok(())
    }
}
