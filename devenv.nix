{ pkgs, lib, config, ... }:

let
  ldapState = "${config.devenv.state}/openldap";
  ldapUrl = "ldap://127.0.0.1:${toString config.processes.openldap.ports.ldap.value}";
  slapdConfig = pkgs.writeText "slapd.conf" ''
    include ${pkgs.openldap}/etc/schema/core.schema
    include ${pkgs.openldap}/etc/schema/cosine.schema
    include ${pkgs.openldap}/etc/schema/inetorgperson.schema
    pidfile "${ldapState}/slapd.pid"
    argsfile "${ldapState}/slapd.args"

    database mdb
    maxsize 1073741824
    suffix "dc=example,dc=org"
    rootdn "cn=admin,dc=example,dc=org"
    rootpw adminpassword
    directory "${ldapState}/data"
    access to attrs=userPassword by anonymous auth by * none
    access to * by * none
  '';
  seed = pkgs.writeText "test-directory.ldif" ''
    dn: dc=example,dc=org
    objectClass: domain
    dc: example

    dn: ou=users,dc=example,dc=org
    objectClass: organizationalUnit
    ou: users

    dn: cn=test_user,ou=users,dc=example,dc=org
    objectClass: inetOrgPerson
    cn: test_user
    sn: User
    userPassword: test_password
  '';
in

{
  languages.rust.enable = true;

  packages = [
    pkgs.cmake
    pkgs.pkg-config
    pkgs.openssl
    pkgs.openldap
  ]
  ++ lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];

  processes.openldap = {
    ports.ldap.allocate = 1389;
    exec = ''
      set -eu
      umask 077
      mkdir -p "${ldapState}/data"
      if [ ! -f "${ldapState}/data/data.mdb" ]; then
        ${pkgs.openldap}/sbin/slapadd -f ${slapdConfig} -l ${seed}
      fi
      printf '%s\n' '${ldapUrl}' > "${ldapState}/url"
      exec ${pkgs.openldap}/libexec/slapd -f ${slapdConfig} -h '${ldapUrl}' -d 0
    '';
    ready = {
      exec = "${pkgs.openldap}/bin/ldapwhoami -x -H ${ldapUrl} -D cn=admin,dc=example,dc=org -w adminpassword";
      period = 1;
      timeout = 30;
    };
  };

  enterTest = ''
    export LDAP_TEST_URL="$(cat "${ldapState}/url")"
    cargo test
    cargo test --no-default-features --features tls-native
    cargo test --no-default-features --features tls-rustls-ring
  '';
}
