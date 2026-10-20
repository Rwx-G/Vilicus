//! The envelope every internal socket shares (spine AD-12): the `Hello` handshake and its answer,
//! requests correlated by `request_id`, writing requests carrying a `call_id` (AD-28), responses,
//! `Cancel` and `Ping`.
//!
//! The handshake has one wire form: the first frame of a connection is a bare [`Hello`], answered
//! by a bare [`HelloReply`]. Neither is a [`Message`], so a `Hello` cannot arrive later in the
//! connection, nor wrapped as one.
//!
//! The bodies of requests and responses are the closed types of each socket's protocol, which
//! later stories define; the envelope is generic over them.

use dcbor::CBOR;
use vilicus_types::{ClientError, Id};

use crate::frame::SocketKind;
use crate::wire::{self, DecodeError, Fields, Wire};

/// A protocol version. A message type evolves only under a new protocol version (AD-12).
pub type ProtocolVersion = u16;

/// The first frame of every connection: who connects and which versions of which protocol it
/// speaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// The protocol of the socket, such as the peer protocol or the audit protocol.
    pub protocol: String,
    /// Every protocol version the peer supports, at least one, in strictly increasing order, so
    /// one set of versions has one encoding.
    pub versions: Vec<ProtocolVersion>,
    /// The systemd unit the peer runs as, as it declares it; the Core checks it against the peer
    /// identity of the socket (AD-24), never trusts it alone.
    pub unit: String,
    /// The build of the peer.
    pub build: String,
}

impl Wire for Hello {
    fn to_cbor(&self) -> CBOR {
        wire::record([
            ("protocol", self.protocol.to_cbor()),
            ("versions", self.versions.to_cbor()),
            ("unit", self.unit.to_cbor()),
            ("build", self.build.to_cbor()),
        ])
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        let mut fields = Fields::open(value, "Hello")?;
        let hello = Self {
            protocol: fields.required("protocol")?,
            versions: fields.required("versions")?,
            unit: fields.required("unit")?,
            build: fields.required("build")?,
        };
        fields.finish()?;
        let increasing = hello.versions.windows(2).all(|pair| pair[0] < pair[1]);
        if hello.versions.is_empty() || !increasing {
            return Err(DecodeError::Invalid {
                type_name: "Hello",
                reason: "versions must be non-empty and strictly increasing",
            });
        }
        Ok(hello)
    }
}

/// Why the Core refuses a `Hello`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloRefusal {
    /// The first frame was not a `Hello`.
    NotHello,
    /// The socket does not serve that protocol.
    UnknownProtocol,
    /// None of the offered versions is one the Core supports.
    NoCommonVersion,
}

impl HelloRefusal {
    /// Every refusal, in declaration order.
    pub const ALL: &'static [Self] =
        &[Self::NotHello, Self::UnknownProtocol, Self::NoCommonVersion];

    /// The refusal's name on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotHello => "not_hello",
            Self::UnknownProtocol => "unknown_protocol",
            Self::NoCommonVersion => "no_common_version",
        }
    }
}

impl Wire for HelloRefusal {
    fn to_cbor(&self) -> CBOR {
        CBOR::from(self.as_str())
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        wire::closed_name(value, "HelloRefusal", Self::ALL, Self::as_str)
    }
}

/// The Core's answer to a `Hello`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloReply {
    /// The version both sides speak from now on.
    Accepted(ProtocolVersion),
    /// The connection is refused; the Core closes it after this frame.
    Refused(HelloRefusal),
}

impl Wire for HelloReply {
    fn to_cbor(&self) -> CBOR {
        match self {
            Self::Accepted(version) => wire::tagged("accepted", version.to_cbor()),
            Self::Refused(reason) => wire::tagged("refused", reason.to_cbor()),
        }
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        const TYPE: &str = "HelloReply";
        let read = wire::variant(value, TYPE)?;
        let payload = read.payload(TYPE)?;
        match read.name {
            "accepted" => ProtocolVersion::from_cbor(payload).map(Self::Accepted),
            "refused" => HelloRefusal::from_cbor(payload).map(Self::Refused),
            _ => Err(read.unknown(TYPE)),
        }
    }
}

/// Chooses the answer to a `Hello`: the highest version both sides support, or a refusal.
pub fn negotiate(hello: &Hello, protocol: &str, supported: &[ProtocolVersion]) -> HelloReply {
    if hello.protocol != protocol {
        return HelloReply::Refused(HelloRefusal::UnknownProtocol);
    }
    hello
        .versions
        .iter()
        .copied()
        .filter(|version| supported.contains(version))
        .max()
        .map_or(
            HelloReply::Refused(HelloRefusal::NoCommonVersion),
            HelloReply::Accepted,
        )
}

/// Reads the message of the first frame of a connection, under the socket kind's item bound: it
/// must decode as a bare `Hello` and nothing else. The caller answers a refusal with
/// [`HelloReply::Refused`] and closes the connection.
pub fn first_frame(message: &[u8], kind: SocketKind) -> Result<Hello, HelloRefusal> {
    wire::decode_with_max_items(message, kind.max_items()).map_err(|_| HelloRefusal::NotHello)
}

/// The body of a request on one socket's protocol: a closed type that says whether it writes.
pub trait RequestBody: Wire {
    /// Whether this request writes. A writing request carries a `call_id` (AD-28), and a request
    /// that does not write carries none.
    fn writes(&self) -> bool;
}

/// A request: correlated by `request_id`, deduplicated by `call_id` when it writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<B> {
    /// Chosen by the caller, unique among its requests in flight; the response carries it back.
    pub request_id: Id,
    /// The caller's call id (AD-28), present exactly when the body writes.
    pub call_id: Option<Id>,
    /// What is asked.
    pub body: B,
}

impl<B: RequestBody> Request<B> {
    /// A request that does not write.
    ///
    /// Returns `None` when the body writes, since such a request needs a `call_id`.
    pub fn read(request_id: Id, body: B) -> Option<Self> {
        (!body.writes()).then_some(Self {
            request_id,
            call_id: None,
            body,
        })
    }

    /// A writing request with the caller's `call_id`.
    ///
    /// Returns `None` when the body does not write, since such a request carries no `call_id`.
    pub fn write(request_id: Id, call_id: Id, body: B) -> Option<Self> {
        body.writes().then_some(Self {
            request_id,
            call_id: Some(call_id),
            body,
        })
    }
}

impl<B: RequestBody> Wire for Request<B> {
    fn to_cbor(&self) -> CBOR {
        let mut fields = vec![
            ("request_id", self.request_id.to_cbor()),
            ("body", self.body.to_cbor()),
        ];
        if let Some(call_id) = &self.call_id {
            fields.push(("call_id", call_id.to_cbor()));
        }
        wire::record(fields)
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        const TYPE: &str = "Request";
        let mut fields = Fields::open(value, TYPE)?;
        let request_id = fields.required("request_id")?;
        let call_id = fields.optional("call_id")?;
        let body: B = fields.required("body")?;
        fields.finish()?;
        match (body.writes(), call_id.is_some()) {
            (true, false) => Err(DecodeError::MissingField {
                type_name: TYPE,
                field: "call_id",
            }),
            (false, true) => Err(DecodeError::Invalid {
                type_name: TYPE,
                reason: "a request that does not write carries no call_id",
            }),
            _ => Ok(Self {
                request_id,
                call_id,
                body,
            }),
        }
    }
}

/// The answer to a request, correlated by its `request_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response<R> {
    /// The `request_id` of the request answered.
    pub request_id: Id,
    /// The result, or the error a client may see (spine conventions, Errors).
    pub result: Result<R, ClientError>,
}

impl<R: Wire> Wire for Response<R> {
    fn to_cbor(&self) -> CBOR {
        wire::record([
            ("request_id", self.request_id.to_cbor()),
            ("result", outcome_to_cbor(&self.result)),
        ])
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        const TYPE: &str = "Response";
        let mut fields = Fields::open(value, TYPE)?;
        let request_id = fields.required("request_id")?;
        let result: Outcome<R> = fields.required("result")?;
        fields.finish()?;
        Ok(Self {
            request_id,
            result: result.0,
        })
    }
}

fn outcome_to_cbor<R: Wire>(result: &Result<R, ClientError>) -> CBOR {
    match result {
        Ok(value) => wire::tagged("ok", value.to_cbor()),
        Err(error) => wire::tagged("error", error.to_cbor()),
    }
}

/// The `result` field of a [`Response`], read as a choice of `ok` or `error`.
struct Outcome<R>(Result<R, ClientError>);

impl<R: Wire> Wire for Outcome<R> {
    fn to_cbor(&self) -> CBOR {
        outcome_to_cbor(&self.0)
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        const TYPE: &str = "Response.result";
        let read = wire::variant(value, TYPE)?;
        let payload = read.payload(TYPE)?;
        match read.name {
            "ok" => R::from_cbor(payload).map(|value| Self(Ok(value))),
            "error" => ClientError::from_cbor(payload).map(|error| Self(Err(error))),
            _ => Err(read.unknown(TYPE)),
        }
    }
}

/// Every message of an internal socket after the handshake. The handshake is not one of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message<B, R> {
    /// A request.
    Request(Request<B>),
    /// A response.
    Response(Response<R>),
    /// Asks the other side to stop working on a request, by its `request_id`.
    Cancel(Id),
    /// A liveness probe; the other side answers `Pong`.
    Ping,
    /// The answer to `Ping`.
    Pong,
}

impl<B: RequestBody, R: Wire> Wire for Message<B, R> {
    fn to_cbor(&self) -> CBOR {
        match self {
            Self::Request(request) => wire::tagged("request", request.to_cbor()),
            Self::Response(response) => wire::tagged("response", response.to_cbor()),
            Self::Cancel(request_id) => wire::tagged(
                "cancel",
                wire::record([("request_id", request_id.to_cbor())]),
            ),
            Self::Ping => CBOR::from("ping"),
            Self::Pong => CBOR::from("pong"),
        }
    }

    fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
        const TYPE: &str = "Message";
        let read = wire::variant(value, TYPE)?;
        match read.name {
            "ping" => read.no_payload(TYPE).map(|()| Self::Ping),
            "pong" => read.no_payload(TYPE).map(|()| Self::Pong),
            "request" => Request::from_cbor(read.payload(TYPE)?).map(Self::Request),
            "response" => Response::from_cbor(read.payload(TYPE)?).map(Self::Response),
            "cancel" => {
                let mut fields = Fields::open(read.payload(TYPE)?, "Cancel")?;
                let request_id = fields.required("request_id")?;
                fields.finish()?;
                Ok(Self::Cancel(request_id))
            }
            _ => Err(read.unknown(TYPE)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use dcbor::{CBORCase, Map};
    use vilicus_types::{ErrorCode, MessageKey, RetryClass, UtcMillis};

    use super::*;
    use crate::profile;
    use crate::wire::{decode, encode};

    /// A request body for the tests: one reading and one writing request.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum SampleBody {
        Get,
        Put(u64),
    }

    impl Wire for SampleBody {
        fn to_cbor(&self) -> CBOR {
            match self {
                Self::Get => CBOR::from("get"),
                Self::Put(value) => wire::tagged("put", value.to_cbor()),
            }
        }

        fn from_cbor(value: &CBOR) -> Result<Self, DecodeError> {
            let read = wire::variant(value, "SampleBody")?;
            match read.name {
                "get" => read.no_payload("SampleBody").map(|()| Self::Get),
                "put" => u64::from_cbor(read.payload("SampleBody")?).map(Self::Put),
                _ => Err(read.unknown("SampleBody")),
            }
        }
    }

    impl RequestBody for SampleBody {
        fn writes(&self) -> bool {
            matches!(self, Self::Put(_))
        }
    }

    pub(crate) type SampleMessage = Message<SampleBody, u64>;

    fn id(n: u8) -> Id {
        Id::new_v7(UtcMillis::UNIX_EPOCH, [n; 10]).expect("UUIDv7")
    }

    pub(crate) fn hello() -> Hello {
        Hello {
            protocol: "vilicus.peer".to_owned(),
            versions: vec![1, 2],
            unit: "vilicus-gateway.service".to_owned(),
            build: "0.0.0".to_owned(),
        }
    }

    /// One message of each kind, for the round-trip and profile tests.
    pub(crate) fn every_message_kind() -> Vec<SampleMessage> {
        let messages = vec![
            Message::Request(Request::read(id(1), SampleBody::Get).expect("reads")),
            Message::Request(Request::write(id(2), id(3), SampleBody::Put(7)).expect("writes")),
            Message::Response(Response {
                request_id: id(2),
                result: Ok(7),
            }),
            Message::Response(Response {
                request_id: id(1),
                result: Err(ClientError {
                    code: ErrorCode::from_static("policy.denied"),
                    message_key: MessageKey::from_static("error.policy.denied"),
                    retry_class: RetryClass::NotRetryable,
                }),
            }),
            Message::Cancel(id(1)),
            Message::Ping,
            Message::Pong,
        ];
        // Stops compiling when a message kind is added, next to the list that must gain it.
        for message in &messages {
            match message {
                Message::Request(_)
                | Message::Response(_)
                | Message::Cancel(_)
                | Message::Ping
                | Message::Pong => {}
            }
        }
        messages
    }

    #[test]
    fn every_message_kind_round_trips() {
        for message in every_message_kind() {
            let bytes = encode(&message).expect("in the profile");
            assert_eq!(decode::<SampleMessage>(&bytes), Ok(message));
        }
    }

    #[test]
    fn every_refusal_round_trips_by_name() {
        for refusal in HelloRefusal::ALL {
            // Stops compiling when a refusal is added, next to `ALL`, which must gain it too.
            match refusal {
                HelloRefusal::NotHello
                | HelloRefusal::UnknownProtocol
                | HelloRefusal::NoCommonVersion => {}
            }
            let bytes = encode(refusal).expect("name");
            assert_eq!(decode::<HelloRefusal>(&bytes).as_ref(), Ok(refusal));
        }
    }

    #[test]
    fn the_highest_common_version_is_chosen() {
        let hello = hello();
        assert_eq!(
            negotiate(&hello, "vilicus.peer", &[1, 2, 3]),
            HelloReply::Accepted(2)
        );
        assert_eq!(
            negotiate(&hello, "vilicus.peer", &[1]),
            HelloReply::Accepted(1)
        );
        assert_eq!(
            negotiate(&hello, "vilicus.peer", &[3]),
            HelloReply::Refused(HelloRefusal::NoCommonVersion)
        );
        assert_eq!(
            negotiate(&hello, "vilicus.audit", &[1, 2]),
            HelloReply::Refused(HelloRefusal::UnknownProtocol)
        );
    }

    /// Every answer to a `Hello`, each in its one bare form.
    pub(crate) fn handshake_replies() -> Vec<HelloReply> {
        HelloRefusal::ALL
            .iter()
            .map(|refusal| HelloReply::Refused(*refusal))
            .chain([HelloReply::Accepted(1)])
            .collect()
    }

    #[test]
    fn the_handshake_round_trips_bare() {
        let bytes = encode(&hello()).expect("hello");
        assert_eq!(decode::<Hello>(&bytes), Ok(hello()));
        for reply in handshake_replies() {
            let bytes = encode(&reply).expect("reply");
            assert_eq!(decode::<HelloReply>(&bytes), Ok(reply));
        }
    }

    /// The handshake has one form: a wrapped `Hello` or `HelloReply` is refused as a first frame
    /// and as any later message, and so is a bare `Hello` after the first frame.
    #[test]
    fn a_wrapped_handshake_is_refused_at_any_point() {
        let wrapped = [
            wire::tagged("hello", hello().to_cbor()),
            wire::tagged("hello_reply", HelloReply::Accepted(1).to_cbor()),
        ];
        for message in wrapped {
            let bytes = profile::encode(&message).expect("in the profile");
            assert_eq!(
                first_frame(&bytes, SocketKind::Control),
                Err(HelloRefusal::NotHello)
            );
            assert!(decode::<SampleMessage>(&bytes).is_err(), "{message:?}");
        }
        let bare = encode(&hello()).expect("hello");
        assert!(decode::<SampleMessage>(&bare).is_err());
    }

    #[test]
    fn hello_versions_are_non_empty_and_strictly_increasing() {
        for versions in [Vec::<u16>::new(), vec![1, 1], vec![2, 1], vec![1, 3, 2]] {
            let value = wire::record([
                ("protocol", CBOR::from("vilicus.peer")),
                ("versions", versions.to_cbor()),
                ("unit", CBOR::from("vilicus-gateway.service")),
                ("build", CBOR::from("0.0.0")),
            ]);
            let bytes = profile::encode(&value).expect("in the profile");
            assert!(
                matches!(decode::<Hello>(&bytes), Err(DecodeError::Invalid { .. })),
                "{versions:?}"
            );
            assert_eq!(
                first_frame(&bytes, SocketKind::Control),
                Err(HelloRefusal::NotHello)
            );
        }
        for versions in [vec![1], vec![1, 2, 7]] {
            let hello = Hello {
                versions,
                ..hello()
            };
            assert_eq!(decode::<Hello>(&encode(&hello).expect("hello")), Ok(hello));
        }
    }

    #[test]
    fn the_first_frame_must_be_a_hello() {
        let bytes = encode(&hello()).expect("hello");
        assert_eq!(first_frame(&bytes, SocketKind::Control), Ok(hello()));
        for other in every_message_kind() {
            let bytes = encode(&other).expect("message");
            assert_eq!(
                first_frame(&bytes, SocketKind::Control),
                Err(HelloRefusal::NotHello)
            );
        }
        let CBORCase::Map(mut map) = hello().to_cbor().into_case() else {
            panic!("a record is a map");
        };
        map.insert("token", "anything");
        let bytes = profile::encode(&CBOR::from(map)).expect("map");
        assert_eq!(
            first_frame(&bytes, SocketKind::Control),
            Err(HelloRefusal::NotHello)
        );
    }

    #[test]
    fn a_writing_request_carries_a_call_id_and_a_reading_one_does_not() {
        assert!(Request::read(id(1), SampleBody::Put(1)).is_none());
        assert!(Request::write(id(1), id(2), SampleBody::Get).is_none());
        let without = wire::record([
            ("request_id", id(1).to_cbor()),
            ("body", SampleBody::Put(1).to_cbor()),
        ]);
        let with = wire::record([
            ("request_id", id(1).to_cbor()),
            ("call_id", id(2).to_cbor()),
            ("body", SampleBody::Get.to_cbor()),
        ]);
        for refused in [without, with] {
            let bytes = profile::encode(&refused).expect("record");
            assert!(decode::<Request<SampleBody>>(&bytes).is_err());
        }
    }

    #[test]
    fn ping_cancel_and_variants_have_one_encoding() {
        let refused = [
            wire::tagged("ping", CBOR::null()),
            wire::tagged(
                "cancel",
                wire::record([
                    ("request_id", id(1).to_cbor()),
                    ("reason", CBOR::from("late")),
                ]),
            ),
            wire::tagged("cancel", id(1).to_cbor()),
            CBOR::from("hello"),
            CBOR::from("Ping"),
            {
                let mut map = Map::new();
                map.insert(3u64, CBOR::from("ping"));
                CBOR::from(map)
            },
        ];
        for message in refused {
            let bytes = profile::encode(&message).expect("in the profile");
            assert!(decode::<SampleMessage>(&bytes).is_err(), "{message:?}");
        }
    }
}
