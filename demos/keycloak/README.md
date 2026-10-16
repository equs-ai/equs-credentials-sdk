### Setup Keycloak

**NOTE**: Keycloak is configured with predefined `pid-issuer-realm` realm and its user(s) will be used while issuing a credential

1. Start keycloak
    ```bash
    docker-compose up -d
    ```
2. Execute below command to disable SSL
    ```bash
     docker exec -d  keycloak /opt/keycloak/bin/kcadm.sh update realms/pid-issuer-realm -s sslRequired=NONE --server http://localhost:8080 --realm master --user admin --password password
    ```
3. Restart the container to apply changes
    ```bash
     docker restart keycloak
    ```