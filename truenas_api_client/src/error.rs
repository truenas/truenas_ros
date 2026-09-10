//! The error vocabulary: what a call, a session, or the transport can
//! report, with middlewared's own error payload decoded rather than handed
//! back as a blob.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt;
use std::io;
use truenas_ros::ws::HandshakeError;

/// middlewared's JSON-RPC error code for "too many concurrent calls" - the
/// per-connection semaphore (soft 10 / hard 20) refusing at the hard limit.
/// Retryable once earlier calls complete.
pub const TOO_MANY_CONCURRENT_CALLS: i64 = -32000;

/// middlewared's JSON-RPC error code for a method call that raised - the
/// interesting one, whose `data` member carries [`CallError`].
pub const CALL_ERROR: i64 = -32001;

/// JSON-RPC 2.0 §5.1's `-32602`, which middlewared answers a validation
/// failure with - carrying the *same* `data` payload as [`CALL_ERROR`],
/// and the only code that carries `extra`
/// (`middlewared/api/base/server/ws_handler/rpc.py`:
/// `send_truenas_validation_error` -> `format_truenas_validation_error` ->
/// `format_truenas_error`). The reference Python client decodes both codes
/// for exactly that reason.
pub const INVALID_PARAMS: i64 = -32602;

/// One entry of a middlewared validation error's `extra` list:
/// `(attribute, message, errno)`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ExtraError(pub String, pub String, pub i64);

/// The `trace` object inside a [`CallError`]: the server-side exception,
/// formatted.
#[derive(Clone, Debug, Deserialize)]
pub struct Trace {
    /// The exception class name.
    #[serde(default)]
    pub class: Option<String>,
    /// The pre-formatted traceback text.
    #[serde(default)]
    pub formatted: Option<String>,
    /// `repr()` of the exception.
    #[serde(default)]
    pub repr: Option<String>,
    /// The structured frames, left undecoded - diagnostic, shape-unstable.
    #[serde(default)]
    pub frames: Option<Value>,
}

/// The decoded `data` payload of a middlewared `-32001` call error.
///
/// Every field is optional by construction: the payload's shape belongs to
/// the server release, and a client that refuses an error because the
/// error's decoration drifted would be manufacturing a second failure out
/// of the first. `message` alone is always present (it is the JSON-RPC
/// `error.message`).
#[derive(Debug)]
#[non_exhaustive]
pub struct CallError {
    /// The JSON-RPC `error.message` (middlewared sends "Method call
    /// error" here; the interesting text is in `reason`).
    pub message: String,
    /// The middleware errno (`data.error`).
    pub errno: Option<i64>,
    /// The errno's symbolic name (`data.errname`, e.g. `EPERM`,
    /// `ENOTAUTHENTICATED`).
    pub errname: Option<String>,
    /// The human-readable failure (`data.reason`).
    pub reason: Option<String>,
    /// The server-side traceback, when the server chose to send one.
    pub trace: Option<Trace>,
    /// Validation failures as `(attribute, message, errno)` triples.
    ///
    /// Populated only when `data.extra` really is that list, which is the
    /// `-32602` shape: `send_truenas_validation_error` passes
    /// `ValidationErrors`, whose `__iter__` yields
    /// `(attribute, errmsg, errno)`. On `-32001` the member is whatever
    /// the raiser handed `CallError(..., extra=...)`, and every raiser in
    /// middlewared hands it a **dict** - `{'dependencies': [...]}` from
    /// `crud_service.py`'s delete-with-dependents, the open-files report
    /// from `pool_/dataset_processes.py`. Those arrive in
    /// [`CallError::extra_raw`] instead of being dropped.
    pub extra: Option<Vec<ExtraError>>,
    /// `data.extra` exactly as the server sent it, whatever its shape.
    ///
    /// Always carries the member when there is one, so nothing the server
    /// put there is lost to a type that did not fit it. [`CallError::extra`]
    /// is this decoded, for the one shape that has a type.
    pub extra_raw: Option<Value>,
}

impl fmt::Display for CallError {
    /// The reason when the server sent one, the generic message
    /// otherwise, with the errname in brackets when known.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.errname {
            write!(f, "[{name}] ")?;
        }
        f.write_str(self.reason.as_deref().unwrap_or(&self.message))
    }
}

/// What went wrong with a call, a session, or the client.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApiError {
    /// The method ran and failed: middlewared's `-32001` with its payload
    /// decoded.
    Call(Box<CallError>),
    /// The parameters did not validate: middlewared's `-32602` with the
    /// same payload decoded. Held apart from [`ApiError::Call`] because
    /// the method never ran - nothing was attempted, so nothing needs
    /// undoing - and because this is the code whose
    /// [`CallError::extra`] carries the per-attribute failures.
    InvalidParams(Box<CallError>),
    /// middlewared refused the call at its per-connection concurrency
    /// hard limit (`-32000`). Retryable once earlier calls finish.
    TooManyConcurrentCalls {
        /// The server's message.
        message: String,
    },
    /// Any other JSON-RPC error object (`-32601` method not found,
    /// `-32602` invalid params, ...).
    Rpc {
        /// The JSON-RPC error code.
        code: i64,
        /// The error message.
        message: String,
        /// The raw `data` member, when present.
        data: Option<Value>,
    },
    /// The WebSocket upgrade failed; the session never opened.
    Handshake(HandshakeError),
    /// The peer violated the protocol (a masked or malformed frame, a
    /// binary frame, a batch answer, a response to no outstanding call,
    /// non-JSON text); the session is closed.
    Protocol(&'static str),
    /// The call's `params` did not serialize to a JSON Array, which is
    /// the only shape middlewared accepts (named params are rejected
    /// server-side).
    ParamsNotArray,
    /// The encoded message exceeds the session's outbound cap. Sending it
    /// anyway would not fail the call - middlewared closes the whole
    /// connection on an oversized message (WS close 1009), taking every
    /// other call with it - so it is refused here instead.
    TooLarge {
        /// The encoded JSON length.
        len: usize,
        /// The session's cap.
        cap: usize,
    },
    /// The call did not complete inside the configured deadline. The
    /// session stays open; a late answer is discarded.
    Timeout,
    /// The session (or the connection under it) closed before the
    /// operation completed.
    Closed {
        /// Why, as far as the transport said.
        reason: String,
    },
    /// A transport-level failure (the ring, the socket, the dial).
    Io(io::Error),
    /// A payload did not decode into the requested type.
    Decode(serde_json::Error),
    /// A queue is at its bound and the work was not accepted: the
    /// deferred [`queue_bulk`](crate::ApiClient::queue_bulk) queue
    /// ([`ApiConfig::max_queued_bulk_items`](crate::ApiConfig::max_queued_bulk_items)),
    /// or a session's own backlog behind its concurrency budget
    /// ([`ApiConfig::max_queued_calls`](crate::ApiConfig::max_queued_calls)).
    /// Retry once earlier work drains.
    QueueFull {
        /// The configured item cap.
        cap: usize,
    },
    /// [`ApiConfig::endpoint`](crate::ApiConfig::endpoint) pins an API
    /// version this client does not speak (see
    /// [`MIN_API_VERSION`](crate::MIN_API_VERSION)).
    UnsupportedApiVersion {
        /// The `(major, minor, patch)` the endpoint pinned.
        pinned: (u32, u32, u32),
        /// The oldest version this client speaks.
        minimum: (u32, u32, u32),
    },
    /// The handle names no live session (already closed, or never this
    /// client's).
    UnknownSession,
    /// The JSON-RPC frame could not be built (a params serializer
    /// failed).
    Build(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call(e) => write!(f, "call failed: {e}"),
            Self::InvalidParams(e) => write!(f, "invalid params: {e}"),
            Self::TooManyConcurrentCalls { message } => {
                write!(f, "too many concurrent calls: {message}")
            }
            Self::Rpc { code, message, .. } => {
                write!(f, "rpc error {code}: {message}")
            }
            Self::Handshake(e) => write!(f, "handshake: {e}"),
            Self::Protocol(what) => write!(f, "protocol violation: {what}"),
            Self::ParamsNotArray => {
                f.write_str("params must serialize to a JSON Array")
            }
            Self::TooLarge { len, cap } => write!(
                f,
                "message of {len} bytes exceeds the {cap}-byte outbound cap \
                 (middlewared closes the connection on oversize)"
            ),
            Self::Timeout => f.write_str("call timed out"),
            Self::QueueFull { cap } => {
                write!(f, "deferred bulk queue is full ({cap} items)")
            }
            Self::Closed { reason } => write!(f, "session closed: {reason}"),
            Self::Io(e) => write!(f, "transport: {e}"),
            Self::Decode(e) => write!(f, "decode: {e}"),
            Self::UnsupportedApiVersion { pinned, minimum } => write!(
                f,
                "endpoint pins API v{}.{}.{}, below the v{}.{}.{} this \
                 client speaks",
                pinned.0, pinned.1, pinned.2, minimum.0, minimum.1, minimum.2
            ),
            Self::UnknownSession => f.write_str("no such session"),
            Self::Build(e) => write!(f, "building the call failed: {e}"),
        }
    }
}

impl std::error::Error for ApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ApiError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        Self::Decode(e)
    }
}

/// Decode a JSON-RPC error object into the [`ApiError`] middlewared meant
/// by it.
pub(crate) fn from_rpc_error(e: &truenas_jsonrpc::ErrorObject) -> ApiError {
    match e.code() {
        CALL_ERROR => ApiError::Call(Box::new(call_error(e))),
        // middlewared builds a validation failure's `data` with the same
        // `format_truenas_error` it uses for -32001, so the same decode
        // applies - and this is the code that actually carries `extra`.
        INVALID_PARAMS => ApiError::InvalidParams(Box::new(call_error(e))),
        TOO_MANY_CONCURRENT_CALLS => ApiError::TooManyConcurrentCalls {
            message: e.message().to_owned(),
        },
        code => ApiError::Rpc {
            code,
            message: e.message().to_owned(),
            data: e.data().cloned(),
        },
    }
}

/// One member of a JSON-RPC `error.data` object, decoded on its own.
///
/// `None` when `data` is absent or not an Object, when the member is absent or
/// `null`, or when it will not decode into `T` - the last of which is the
/// point: JSON-RPC 2.0 §5.1 leaves `data` entirely to the server, so a client
/// must be able to lose one drifted member without losing the rest.
fn member<T: DeserializeOwned>(data: Option<&Value>, name: &str) -> Option<T> {
    data.and_then(Value::as_object)
        .and_then(|m| m.get(name))
        .filter(|v| !v.is_null())
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// Decode middlewared's TrueNAS error payload out of an error object's
/// `data`, one member at a time (see [`member`]).
///
/// Shared by the two codes that carry that payload: `-32001`, and `-32602`,
/// which is the one that actually delivers `extra`. Per-member decoding
/// matters most here - a validation failure's `extra` is the part most likely
/// to gain a field, and losing it must not also lose `errname`.
fn call_error(e: &truenas_jsonrpc::ErrorObject) -> CallError {
    let data = e.data();
    CallError {
        message: e.message().to_owned(),
        errno: member(data, "error"),
        errname: member(data, "errname"),
        reason: member(data, "reason"),
        trace: member(data, "trace"),
        extra: member(data, "extra"),
        extra_raw: data
            .and_then(Value::as_object)
            .and_then(|m| m.get("extra"))
            .filter(|v| !v.is_null())
            .cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use truenas_jsonrpc::ErrorObject;

    /// middlewared's validation failure: -32602 with the full TrueNAS
    /// payload, including the per-attribute `extra` list. It decodes like
    /// -32001 rather than being handed back as an opaque blob.
    /// `-32001`'s `extra` is whatever the raiser passed
    /// `CallError(..., extra=...)`, and every middlewared raiser passes a
    /// dict - the delete-with-dependents report, the open-files list.
    /// The typed field cannot hold one; the raw field must not lose it.
    #[test]
    fn a_dict_extra_survives_as_raw() {
        let e = ErrorObject::new(CALL_ERROR, "Method call error").with_data(
            serde_json::json!({
                "error": 16,
                "errname": "EBUSY",
                "reason": "Device busy",
                "extra": { "dependencies": ["share/smb/1"] },
            }),
        );
        match from_rpc_error(&e) {
            ApiError::Call(err) => {
                // The members around it still decode.
                assert_eq!(err.errname.as_deref(), Some("EBUSY"));
                assert_eq!(err.reason.as_deref(), Some("Device busy"));
                // The dict does not fit the typed shape...
                assert!(err.extra.is_none());
                // ...and is therefore the thing that must not be dropped.
                let raw = err.extra_raw.expect("the dict reaches the caller");
                assert_eq!(raw["dependencies"][0], "share/smb/1");
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    /// The `-32602` shape still decodes into the typed field, and the raw
    /// one carries it too - one member, two views.
    #[test]
    fn a_list_extra_decodes_and_is_also_raw() {
        let e = ErrorObject::new(INVALID_PARAMS, "Invalid params").with_data(
            serde_json::json!({
                "extra": [["pool_create.name", "Invalid", 22]],
            }),
        );
        match from_rpc_error(&e) {
            ApiError::InvalidParams(err) => {
                let typed = err.extra.expect("the triple decodes");
                assert_eq!(typed[0].0, "pool_create.name");
                assert_eq!(typed[0].2, 22);
                assert!(err.extra_raw.is_some(), "raw carries it too");
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    #[test]
    fn a_validation_error_decodes_its_payload() {
        let e = ErrorObject::new(INVALID_PARAMS, "Invalid params").with_data(
            json!({
                "error": 22,
                "errname": "EINVAL",
                "reason": "[EINVAL] pool_create.name: Invalid name",
                "trace": { "class": "ValidationErrors" },
                "extra": [["pool_create.name", "Invalid name", 22]]
            }),
        );
        match from_rpc_error(&e) {
            ApiError::InvalidParams(err) => {
                assert_eq!(err.errno, Some(22));
                assert_eq!(err.errname.as_deref(), Some("EINVAL"));
                assert_eq!(
                    err.reason.as_deref(),
                    Some("[EINVAL] pool_create.name: Invalid name")
                );
                assert_eq!(
                    err.to_string(),
                    "[EINVAL] [EINVAL] pool_create.name: Invalid name"
                );
                let extra = err.extra.expect("the attribute failures");
                assert_eq!(extra[0].0, "pool_create.name");
                assert_eq!(extra[0].2, 22);
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    /// A -32602 with no `data` at all (a peer that is not middlewared)
    /// still decodes, carrying just the message.
    #[test]
    fn a_bare_invalid_params_still_decodes() {
        let e = ErrorObject::new(INVALID_PARAMS, "Invalid params");
        match from_rpc_error(&e) {
            ApiError::InvalidParams(err) => {
                assert_eq!(err.message, "Invalid params");
                assert!(err.reason.is_none() && err.extra.is_none());
            }
            other => panic!("expected InvalidParams, got {other:?}"),
        }
    }

    /// Codes with no TrueNAS payload stay opaque.
    #[test]
    fn an_unknown_code_stays_opaque() {
        let e = ErrorObject::new(-32601, "Method not found");
        assert!(matches!(
            from_rpc_error(&e),
            ApiError::Rpc { code: -32601, .. }
        ));
    }
}
