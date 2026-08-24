# Overview

It is possible to run tests locally or remote.

- For local installation look for installation [guideline](#installation)
- For remote - follow test [documentation](conformance-tests)

- Check for tests availability [here](https://openid.net/how-to-certify-your-implementation/).
- [Extra guideline](https://imalsha-sg.medium.com/a-guide-to-run-the-oidc-conformance-suite-with-wso2-identity-server-382ece6e8df4)

## Installation

- Conformance Suite [source code](https://gitlab.com/openid/conformance-suite).
- Installation, building & run [guideline](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run).

Recommended to install with Docker in order to avoid problems with Java, Maven and other tools' installation.

Keycloak [docker-compose](../../demos/keycloak/docker-compose.yaml) uses 8443 port. In order to avoid collision with
Conformance Suite change it to any free port (
e.g. 39000:8443).

Open [https://localhost.emobix.co.uk:8443/index.html](https://localhost.emobix.co.uk:8443/index.html).

That's it, you have installed Conformance-Suite and can run tests locally.

## Run tests

Create test plan or use existing one.

Every parameter has its own description that may help you with testing.

How to work with testing you may find in its [documentation](conformance-tests).

## Results

In the end you should see Finished & Passed badges at the top.

If you have Waiting, Interrupted or Failed badges - test did not pass, and you should look for the problem.