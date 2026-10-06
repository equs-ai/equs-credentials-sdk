### Setup Keycloak

**NOTE**: Keycloak is configured with predefined `pid-issuer-realm` realm and its user(s) will be used while issuing a credential

1. Choose an admin password and start keycloak
    ```bash
    export KEYCLOAK_ADMIN_PASSWORD=<password>
    docker-compose up -d
    ```
2. Execute below command to disable SSL
    ```bash
     docker exec -d  keycloak /opt/keycloak/bin/kcadm.sh update realms/pid-issuer-realm -s sslRequired=NONE --server http://localhost:8080 --realm master --user admin --password "$KEYCLOAK_ADMIN_PASSWORD"
    ```
3. Restart the container to apply changes
    ```bash
     docker restart keycloak
    ```