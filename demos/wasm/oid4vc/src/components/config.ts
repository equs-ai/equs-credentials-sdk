import { Claims } from "@equs/equs-sdk";

export class Config {
  readonly servers = {
    issuer: {
      host: "localhost",
      port: 35001,
    },
    verifier: {
      host: "localhost",
      port: 35003,
    },
  };

  readonly clientId = "wallet-dev";

  readonly issuerServerUrl = `http://${this.servers.issuer.host}:${this.servers.issuer.port}`;

  readonly claims: Claims = {
    given_name: "John",
    family_name: "Doe",
    email: "john@doe.com",
    username: "john_doe",
  };
}

export const config = new Config();
