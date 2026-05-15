# didcomm::protocol::outofband — Context

## Purpose
Implements the Out-of-Band 2.0 protocol (`out-of-band/2.0`). Provides invitation creation (Inviter), invitation acceptance (Invitee), connection establishment, and invitation parsing from URL or JSON.

## Files

| File | Role |
|------|------|
| `mod.rs` | `OutOfBandV2Protocol`, all data types, `Protocol` impl (no handlers), invitation helpers |

## Key types / traits

### `OutOfBandV2Protocol<KMS, KH, C>`
Created via `OutOfBandV2Protocol::new(agent)`.

```
create_invitation(config: InvitationConfig) → (Url, ConnectionRecord)
accept_invitation(invitation, key_type)     → ConnectionRecord
establish_connection(connection_id, their_did, key_type) → ()
parse_invitation(str)                       → Invitation
```

`create_invitation` flow:
1. Creates a `did:peer:4` DID with Authentication + Assertion + KeyAgreement + DIDCommMessaging service.
2. Builds an `Invitation` and a `ConnectionRecord` (Inviter, Invited).
3. Base64url-encodes the invitation JSON as `?_oob=<encoded>` query param.
4. Emits `INVITATION_CREATED_EVENT`.

`accept_invitation` flow:
1. Resolves inviter's DID document.
2. Creates a local `did:peer:4` DID.
3. Creates `ConnectionRecord` (Invitee, Accepted).

`establish_connection`: advances connection from `Invited`/`Accepted` → `Completed`; sets `their_did`.

`parse_invitation`: handles `?_oob=` URL param or raw JSON; validates `type_` == `INVITATION_TYPE`.

`get_message_handlers()` returns `vec![]` — OOB invitations are exchanged out-of-band, not as DIDComm messages.

### Data types
- `Invitation { id, type_, from, body: InvitationBody, attachments }`
- `InvitationBody { goal_code, goal, accept }`
- `InvitationConfig { key_type, label, goal, goal_code, attachments }`
- `Event::InvitationReceived | InvitationCreated | InvitationAccepted`

## Protocol constants
```
PROTOCOL_NAME          = "out-of-band"
PROTOCOL_VERSION       = "2.0"
INVITATION_TYPE        = "https://didcomm.org/out-of-band/2.0/invitation"
INVITATION_CREATED_EVENT  = "oob-invitation-created"
INVITATION_ACCEPTED_EVENT = "oob-invitation-accepted"
INVITATION_RECEIVED_EVENT = "oob-invitation-received"
```

## Dependencies
- Depends on: `crate::did::{DIDPeer, UniversalResolver}`, `crate::didcomm::connection::ConnectionService`, `crate::didcomm::agent::Agent`, `crate::kms`
- Used by: `aries::issuance`, `aries::present_proof` (both roles embed `OutOfBandV2Protocol`)

## Constraints
- Non-wasm only.
