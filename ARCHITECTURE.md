# Architecture

## Module Dependency Graph

```
┌──────────────────────────────────────────────────┐
│                  sample-app                      │
│  (MinimalWalletActivity, ViewModels)             │
└──────────┬───────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────┐
│                  sdk:wallet                      │
│  SirosWallet — top-level orchestrator            │
│  Combines all modules into a single API          │
├──────────┬──────┬──────┬──────┬──────────────────┤
│          │      │      │      │                  │
│  ┌───────▼──┐ ┌─▼────┐│┌─────▼─────┐┌───────────▼┐
│  │sdk:flow  │ │sdk:  ││ │sdk:       ││sdk:        │
│  │FlowClient│ │auth  ││ │keystore   ││credentials │
│  └────┬─────┘ └──┬───┘│ └───────────┘└────────────┘
│       │          │     │                           │
│  ┌────▼──────────▼─────▼───────────────────────┐  │
│  │           sdk:transport                     │  │
│  │  WmpSession, WmpCodec, WebSocketTransport   │  │
│  └─────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────┘

┌───────────────────────────────────┐
│      sdk:passkey-provider         │
│  Android CredentialProvider       │
│  Service (standalone)             │
│  depends on: sdk:auth             │
└───────────────────────────────────┘
```

## Two APIs

`sdk:wallet` is a facade, not the only entry point. Hosts that already run
the OID4VCI/OID4VP flows (a web-view wrapper around the SIROS web wallet, an
app with its own protocol client) compose `sdk:keystore`, `sdk:auth` and
`sdk:credentials` directly and never construct `SirosWallet` - which is what
pulls `sdk:flow` and the engine conversation in. Both are supported and
covered by the API dump; see [docs/TWO-APIS.md](docs/TWO-APIS.md).

## Module Responsibilities

### sdk:transport
- WMP (Wallet Message Protocol) client over WebSocket
- JSON-RPC 2.0 codec with request-response correlation
- Automatic reconnection with session resumption
- Engine session management (WalletEngineSession)
- Engine-blind encryption wire shapes (`CredentialResponseEncryptionRequest`, `ResponseEncryptionRequest`, `VerifiedRequest`): the wallet holds the issuance response key and builds the encrypted presentation response, the engine relays ciphertext only

### sdk:auth
- WebAuthn/FIDO2 registration and authentication
- AuthProvider protocol for platform-specific passkey implementations
- BackendApiClient for REST communication with wallet backend
- WebAuthnAuthClient for WebAuthn challenge/response flows

### sdk:keystore
- JWE-encrypted credential storage
- HKDF key derivation from WebAuthn PRF output
- SD-JWT VP token signing with key binding
- Secure key material lifecycle management

### sdk:flow
- OID4VCI (credential issuance) flow handling
- OID4VP (credential presentation) flow handling
- Flow event translation from WMP messages
- Credential selection and disclosure logic

### sdk:credentials
- Credential storage (CredentialStore protocol)
- DCQL (Digital Credentials Query Language) matching
- VCTM (Verifiable Credential Type Metadata) fetching
- SD-JWT parsing and validation utilities
- Base exception hierarchy (SirosException)

### sdk:wallet
- SirosWallet: top-level API for host applications
- Session management (login, logout, token refresh)
- Flow orchestration (accept/reject issuance/presentation)
- Private data sync with backend
- Event listener pattern for UI updates

### sdk:passkey-provider
- Android CredentialProvider Service
- Surfaces SIROS credentials in Android's system credential picker
- Standalone module that depends on sdk:auth

## Threading Model

- All SDK operations are `suspend` functions running on `Dispatchers.IO`
- WmpSession uses coroutine channels for message routing
- UI callbacks (WalletEventListener) are delivered on the calling dispatcher
- BackendApiClient uses OkHttp for synchronous HTTP on IO dispatcher

## Error Model

All SDK exceptions extend `SirosException`:
- `NetworkException` — connectivity failures
- `AuthException` — authentication/authorization errors
- `KeystoreException` — key material or crypto errors
- `WalletException` — orchestration-level errors
- `BackendApiException` — HTTP API errors with status code
- `WmpSessionException` — WMP protocol errors
- `WmpTimeoutException` — request timeout errors

## Security Model

1. **Key derivation**: WebAuthn PRF → HKDF-SHA256 → AES-256 main key
2. **Credential storage**: JWE-encrypted containers (A256GCM)
3. **Token handling**: Short-lived app tokens, refresh tokens in session store
4. **Transport**: WSS (WebSocket Secure) with TLS
5. **Logging**: Sensitive data (credential IDs, tokens, session UUIDs) redacted
