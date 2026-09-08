//! The error vocabulary: what a call, a session, or the transport can
//! report, with middlewared's own error payload decoded rather than handed
//! back as a blob.

use serde::Deserialize;
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
    pub extra: Option<Vec<ExtraError>>,
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
    /// The deferred [`queue_bulk`](crate::ApiClient::queue_bulk) queue is
    /// at its bound; the item was not queued. Retry once earlier items
    /// flush.
    QueueFull {
        /// The configured item cap.
        cap: usize,
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
        CALL_ERROR => {
            // The data payload's fields, each independently optional.
            #[derive(Deserialize)]
            struct Data {
                #[serde(default)]
                error: Option<i64>,
                #[serde(default)]
                errname: Option<String>,
                #[serde(default)]
                reason: Option<String>,
                #[serde(default)]
                trace: Option<Trace>,
                #[serde(default)]
                extra: Option<Vec<ExtraError>>,
            }
            let data: Option<Data> = e
                .data()
                .and_then(|d| serde_json::from_value(d.clone()).ok());
            let data = data.unwrap_or(Data {
                error: None,
                errname: None,
                reason: None,
                trace: None,
                extra: None,
            });
            ApiError::Call(Box::new(CallError {
                message: e.message().to_owned(),
                errno: data.error,
                errname: data.errname,
                reason: data.reason,
                trace: data.trace,
                extra: data.extra,
            }))
        }
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
