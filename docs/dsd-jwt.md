# About dSD-JWT Delegation

See [Five-party demo](../demos/oid4vc/README.md#delegated-sd-jwt-dsd-jwt-demo) for a working demo of dSD-JWT for agentic use cases.

## Overview
dSD-JWT — a delegated SD-JWT — is a general-purpose mechanism for one party to hand a bounded, verifiable authorisation to another party, on top of a credential it already holds.
A Holder who was issued an SD-JWT VC can append a signed delegation hop to it, carrying arbitrary claims and, optionally, the public key of the party being delegated to.
The result is still one compact credential, and every hop in it traces back to the original Issuer signature.
The point is that the Issuer is not involved. Delegation is a Holder-side act: no re-issuance, no new credential type, no call back to whoever issued the root credential.

A delegation is requested as an OID4VP transaction_data item, so it travels inside an ordinary presentation exchange: the Verifier asks for a credential and, in the same request, for the Holder to sign a delegation over it. No separate protocol, no separate endpoint.

**Note:** dSD-JWT is a primitive, not a business feature. It says nothing about what the delegated claims mean. Higher-level features define that vocabulary; AP2 is the first of them.

## How a delegation hop works
Start from a regular Issuer-signed SD-JWT VC. A delegation adds one hop on top of it:
1. The Holder signs a delegate payload — a set of claims describing what is being authorised — with the key the credential is bound to.
2. If the hop is bound, the payload carries a cnf holding the public key of the party being delegated to. Only the holder of that private key can add a further hop.
3. If the hop is terminal, there is no cnf. The claims are attested and the chain ends there — nothing is delegated onward.

The delegate payloads are carried as SD-JWT disclosures, so a credential can hold several alternative payloads side by side.

## The two formats

Every delegation item declares a format, and that single choice decides whether authority continues past this hop:

| Format | Meaning | `delegateJwk` | Result |
| --- | --- | --- | --- |
| `dSD-JWT+KB` | Holder binding | **Required** | The payload gets a `cnf` naming the delegate key. That delegate can later extend or close the chain. |
| `dSD-JWT` | Terminal | Not used | No `cnf`. The payload is attested to the Verifier and confers no onward authority. |

The choice is per item, and the API enforces it structurally: `DelegationRequest::holder_binding` takes the delegate's public key, `DelegationRequest::open` takes none. What is checked, at verification time, is that the alternatives disclosed on the final hop are exactly the `delegate` items the Verifier requested for that credential.

## Alternatives on one credential
Several delegation items may name the same credential in their `credential_ids`. They then describe alternatives over that credential: all of them are signed into the grant, so a single approval can pre-authorise several mutually exclusive options.
Items naming different credentials are independent — they attach to different credentials in the same Presentation Request.

Narrowing that menu down to one alternative when the grant is presented onward is not supported yet — the check above rejects a partially disclosed menu. A stored menu grant can be received and re-delegated, but not presented narrowed.
