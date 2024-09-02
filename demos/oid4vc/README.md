# SDK Demo - OID4VC Service
This Demo allows to demonstrate the end-to-end flow of the OID4VCI/VP protocol.
The Web server in the root represents the Issuer and Verifier sides and the holder folder contains the Holder side.

### Setup Keycloak

**NOTE**: Keycloak is configured with predefined `pid-issuer-realm` realm and its user(s) will be used while issuing a credential

1. Go to `docker-compose` folder:
    ```bash
    cd  docker-compose
    ```
2. Start keycloak
    ```bash
    docker-compose up 
    ```
3. Execute below command to disable SSL
    ```bash
     docker exec -d  keycloak /opt/keycloak/bin/kcadm.sh update realms/pid-issuer-realm -s sslRequired=NONE --server http://localhost:8080/idp --realm master --user admin --password password
    ```
4. Restart the container to apply changes
    ```bash
     docker restart  keycloak
    ```

### Steps to run the demo

1. Run a web server:
    ```bash
    cargo run
    ```
2. Open a new terminal window. Go to the `holder` folder and run demo
    ```bash
    cd  holder
    cargo run
    ```
3. Follow the instructions on the console.