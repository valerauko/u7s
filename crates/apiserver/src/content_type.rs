// content_type.rs — Tower middleware for Kubernetes protobuf content negotiation.
//
// Kubelet 1.36+ sends `Accept: application/vnd.kubernetes.protobuf, application/json`
// on every request.  The ContentTypeService middleware below validates incoming requests
// and passes responses through unchanged — it does not touch response bodies.
//
// A prior response-side re-encoder was reverted 2026-05-21 (commit 51d54dec) after a
// client-go decoder crash: that encoder wrapped the *JSON* bytes inside a protobuf
// `Unknown` envelope's `raw` field, relying on client-go reading `Unknown.contentType`
// to know to re-decode `raw` as JSON — but client-go's typed proto decoders ignore that
// field and attempt to decode `raw` as a native proto message, producing
// "proto: illegal wireType N" when JSON bytes happen to align to invalid wire types.
//
// `negotiated_response` below is not that mechanism: it dispatches to a real per-type
// protobuf encoder (`encoders()`) that produces a genuine protobuf-encoded object in
// `Unknown.raw`, for a deliberately small set of hot-path kinds (see `encoders()`).
// Kinds without a registered encoder — including every kind this middleware used to
// mis-encode — fall back to plain JSON, which is always a valid response since the
// client's Accept header lists "application/json" too.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Request, Response};
use axum::response::IntoResponse;
use tower::Layer;
use tower_service::Service;

// ---------------------------------------------------------------------------
// Response-side protobuf encoding for hot-path GET/LIST kinds
// ---------------------------------------------------------------------------

type EncoderFn = fn(&serde_json::Value) -> Vec<u8>;

/// `(apiVersion, kind)` -> protobuf encoder, mirroring `proto::decoders()`'s dispatch shape but
/// for the response direction. Deliberately scoped to the hot-path kinds named in the bead
/// rather than the full ~65-kind decode surface — see `core_gen_adapter`/
/// `net_disc_cert_policy_events_gen_adapter`'s `encode_*_proto_gen` doc comments for the
/// field-coverage scope of each encoder.
///
/// Keyed by the pair, not `kind` alone: `events.k8s.io/v1.Event`/`EventList` share the exact
/// `kind` string "Event"/"EventList" with the legacy `/api/v1` core Event/EventList this table
/// also serves, but are unrelated proto messages with different field numbers entirely. A
/// `kind`-only key sent every `events.k8s.io/v1` Event LIST through the core `v1.Event` proto
/// schema instead — decodable by our own decoder (which shares the same mistake) but not by a
/// real client-go typed `EventsV1` client, which failed with "proto: wrong wireType = 2 for
/// field Nanos" trying to parse core Event's bytes as `events.k8s.io/v1.Event`.
fn encoders() -> &'static std::collections::HashMap<(&'static str, &'static str), EncoderFn> {
    static ENCODERS: std::sync::OnceLock<
        std::collections::HashMap<(&'static str, &'static str), EncoderFn>,
    > = std::sync::OnceLock::new();
    ENCODERS.get_or_init(|| {
        let mut m: std::collections::HashMap<(&'static str, &'static str), EncoderFn> =
            std::collections::HashMap::new();
        m.insert(
            ("v1", "Pod"),
            crate::core_gen_adapter::encode_pod_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "PodList"),
            crate::core_gen_adapter::encode_podlist_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "Service"),
            crate::core_gen_adapter::encode_service_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "ServiceList"),
            crate::core_gen_adapter::encode_servicelist_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "Node"),
            crate::core_gen_adapter::encode_node_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "NodeList"),
            crate::core_gen_adapter::encode_nodelist_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "Endpoints"),
            crate::core_gen_adapter::encode_endpoints_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "EndpointsList"),
            crate::core_gen_adapter::encode_endpointslist_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "Event"),
            crate::core_gen_adapter::encode_event_proto_gen as EncoderFn,
        );
        m.insert(
            ("v1", "EventList"),
            crate::core_gen_adapter::encode_eventlist_proto_gen as EncoderFn,
        );
        m.insert(
            ("discovery.k8s.io/v1", "EndpointSlice"),
            crate::net_disc_cert_policy_events_gen_adapter::encode_endpointslice_proto_gen
                as EncoderFn,
        );
        m.insert(
            ("discovery.k8s.io/v1", "EndpointSliceList"),
            crate::net_disc_cert_policy_events_gen_adapter::encode_endpointslicelist_proto_gen
                as EncoderFn,
        );
        m
    })
}

/// Whether `accept` names the Kubernetes protobuf media type.
pub fn wants_protobuf(accept: &str) -> bool {
    accept.contains("application/vnd.kubernetes.protobuf")
}

/// Whether `(api_version, kind)` has a registered protobuf encoder in [`encoders()`].
///
/// Callers that build a response body themselves (rather than going through
/// [`negotiated_response`]) — e.g. a LIST handler deciding whether it's safe to stream
/// straight to JSON bytes without ever materializing a parsed `Value` tree — need this
/// answer BEFORE building the body. Real clients (kubelet/client-go) send a combined
/// `Accept: application/vnd.kubernetes.protobuf, application/json`, so `wants_protobuf`
/// alone can't tell a kind that will actually get protobuf apart from one that's about to
/// fall back to JSON anyway; only a kind present in `encoders()` needs the non-streaming
/// path.
pub fn has_encoder(api_version: &str, kind: &str) -> bool {
    encoders().contains_key(&(api_version, kind))
}

/// Build the response body for an already-assembled JSON object, honoring protobuf content
/// negotiation for the hot-path kinds registered in `encoders()`.
///
/// Falls back to plain `axum::Json` whenever `accept` does not request protobuf, `obj` has
/// no (or an unrecognized) `kind`, or the kind has no registered encoder — this mirrors the
/// pre-existing behavior for every kind this function doesn't special-case, so migrating a
/// call site to use it cannot regress a client that only ever spoke JSON.
pub fn negotiated_response(accept: &str, obj: serde_json::Value) -> Response<Body> {
    if wants_protobuf(accept) {
        if let Some(kind) = obj.get("kind").and_then(|k| k.as_str()) {
            let api_version = obj.get("apiVersion").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(encoder) = encoders().get(&(api_version, kind)) {
                let raw = encoder(&obj);
                let body = crate::proto::encode_k8s_envelope(kind, api_version, raw);
                return (
                    [(header::CONTENT_TYPE, "application/vnd.kubernetes.protobuf")],
                    body,
                )
                    .into_response();
            }
        }
    }
    axum::Json(obj).into_response()
}

// ---------------------------------------------------------------------------
// ContentTypeLayer
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ContentTypeLayer;

impl<S> Layer<S> for ContentTypeLayer {
    type Service = ContentTypeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ContentTypeService { inner }
    }
}

// ---------------------------------------------------------------------------
// ContentTypeService
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ContentTypeService<S> {
    inner: S,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<S> Service<Request<Body>> for ContentTypeService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let method = req.method().clone();
        // `uri` intentionally includes the query string: none of this apiserver's routes
        // accept bearer tokens or secrets as query parameters (auth is Authorization-header
        // or client-cert only; the only query params in use are things like timeout,
        // fieldSelector, labelSelector, watch, limit, continue), so there is no credential
        // leakage risk in logging it verbatim.
        let uri = req.uri().to_string();
        let user_agent = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let request_id = uuid::Uuid::new_v4();
        let start = std::time::Instant::now();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut resp = inner.call(req).await?;

            // Single access-log point for every request — keeps the field set/level
            // consistent and ensures the status logged is the one actually returned
            // to the client, not an intermediate value.
            let status = resp.status().as_u16();
            let request_id_str = request_id.to_string();

            // Watch/streaming responses (Transfer-Encoding: chunked) must be passed
            // through with headers completely untouched: the response's `Body` here
            // is a long-lived stream backed by a broadcast receiver that was subscribed
            // before this middleware ever ran, so any per-response bookkeeping added
            // here must not touch it. Mutating the header map is header-only and would
            // never touch body bytes, but every other response class on this server is
            // fully buffered by its handler by the time it reaches here, and watch is
            // the one case where "the response" is still an in-progress operation
            // rather than a finished value — so it gets the same "leave it alone"
            // treatment.
            let is_streaming = resp
                .headers()
                .get(header::TRANSFER_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(|te| te.eq_ignore_ascii_case("chunked"))
                .unwrap_or(false);
            if !is_streaming {
                if let Ok(value) = HeaderValue::from_str(&request_id_str) {
                    resp.headers_mut()
                        .insert(HeaderName::from_static("x-request-id"), value);
                }
            }
            tracing::info!(
                method = %method,
                uri = %uri,
                status,
                user_agent = %user_agent,
                latency_ms = start.elapsed().as_millis() as u64,
                request_id = %request_id_str,
                "request"
            );
            Ok(resp)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::encode_proto_response;
    use axum::body::Body;
    use axum::http::{Method, Request, Response, StatusCode};
    use std::task::{Context, Poll};
    use tower::Layer;
    use tower_service::Service;

    // Minimal inner service that returns a configurable response.
    #[derive(Clone)]
    struct FixedService {
        status: StatusCode,
        content_type: &'static str,
        body: &'static str,
    }

    impl Service<Request<Body>> for FixedService {
        type Response = Response<Body>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Body>) -> Self::Future {
            let status = self.status;
            let ct = self.content_type;
            let body = self.body;
            Box::pin(async move {
                Ok(Response::builder()
                    .status(status)
                    .header("content-type", ct)
                    .body(Body::from(body))
                    .unwrap())
            })
        }
    }

    fn proto_accept_request() -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/nodes/my-node")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap()
    }

    fn json_accept_request() -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/nodes/my-node")
            .header("accept", "application/json")
            .body(Body::empty())
            .unwrap()
    }

    const SAMPLE_JSON: &str =
        r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"my-namespace"}}"#;

    /// A 2xx JSON response with Accept: protobuf must be passed through as JSON unchanged.
    ///
    /// client-go's typed proto decoders do not reliably honour the contentType=application/json
    /// field inside a proto Unknown envelope — they attempt to decode Unknown.raw as a native
    /// typed proto message and produce "proto: illegal wireType N" when JSON bytes happen to
    /// align to invalid wire types.  Returning JSON is always valid: the client's Accept header
    /// includes "application/json" as a fallback, and client-go falls back to its JSON decoder
    /// transparently.
    #[tokio::test]
    async fn proto_accept_2xx_json_is_passed_through_as_json() {
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let resp = layer_svc.call(proto_accept_request()).await.unwrap();

        // Content-Type must remain application/json — not converted to proto.
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "content-type must remain application/json — typed proto decoders produce \
             wireType errors when JSON bytes are mis-read as proto field tags"
        );

        // Body must be the original JSON unchanged.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "response body must not start with k8s proto magic"
        );
        assert_eq!(
            body.as_ref(),
            SAMPLE_JSON.as_bytes(),
            "response body must be the original JSON unchanged"
        );
    }

    /// A 4xx error response must NOT be re-encoded — client-go always reads errors as JSON.
    ///
    /// Re-encoding errors as protobuf would break kubectl error display and controller error
    /// handling, since the Status object is only parsed from JSON by the client error path.
    #[tokio::test]
    async fn proto_accept_4xx_response_is_not_re_encoded() {
        let error_body = r#"{"apiVersion":"v1","kind":"Status","status":"Failure","code":404}"#;
        let svc = FixedService {
            status: StatusCode::NOT_FOUND,
            content_type: "application/json",
            body: error_body,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let resp = layer_svc.call(proto_accept_request()).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "4xx responses must remain JSON even when client accepts protobuf"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "4xx response body must not start with k8s proto magic"
        );
    }

    /// A 2xx JSON response without Accept: protobuf must NOT be re-encoded.
    ///
    /// Plain kubectl or controller clients that use JSON must receive JSON — re-encoding
    /// them unconditionally would break every client that doesn't speak protobuf.
    #[tokio::test]
    async fn json_accept_2xx_response_is_not_re_encoded() {
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let resp = layer_svc.call(json_accept_request()).await.unwrap();

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "response must remain JSON when client does not accept protobuf"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "body must not start with k8s proto magic when client does not accept protobuf"
        );
    }

    /// When the inner response carries a Content-Length header and the middleware passes it
    /// through as JSON, the Content-Length must be preserved unchanged.
    ///
    /// Previously, the middleware would re-encode the body as proto (larger) and update
    /// Content-Length to the proto length.  Since we now pass JSON through unchanged,
    /// Content-Length should equal the original JSON byte count.
    #[tokio::test]
    async fn content_length_is_preserved_on_json_pass_through() {
        #[derive(Clone)]
        struct ServiceWithContentLength;
        impl Service<Request<Body>> for ServiceWithContentLength {
            type Response = Response<Body>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: Request<Body>) -> Self::Future {
                let body = SAMPLE_JSON;
                Box::pin(async move {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header("content-length", body.len().to_string())
                        .body(Body::from(body))
                        .unwrap())
                })
            }
        }

        let mut layer_svc = ContentTypeLayer.layer(ServiceWithContentLength);
        let resp = layer_svc.call(proto_accept_request()).await.unwrap();

        // Content-Length must equal the original JSON length (body is unchanged).
        let cl_header = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("Content-Length must be preserved")
            .to_str()
            .expect("Content-Length must be a valid string")
            .parse::<usize>()
            .expect("Content-Length must be a valid integer");

        assert_eq!(
            cl_header,
            SAMPLE_JSON.len(),
            "Content-Length must equal the original JSON byte count since body is unchanged"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), SAMPLE_JSON.as_bytes());
    }

    /// Regression test for "illegal wireType 6": when Content-Length is the JSON byte length but
    /// the proto body is larger, truncating to json_len bytes produces a malformed protobuf stream.
    ///
    /// This test proves three things:
    ///   1. encode_proto_response always produces MORE bytes than the source JSON (so the old
    ///      Content-Length was always wrong).
    ///   2. A read truncated to the original json_len bytes fails to decode as a k8s proto
    ///      envelope — this is the wireType 6 scenario the kubectl CI gate hit.
    ///   3. The full (untruncated) bytes decode correctly — the fix (removing Content-Length) lets
    ///      the client read all bytes and succeed.
    ///
    /// If the Content-Length removal is reverted, content_length_is_removed_on_re_encode catches
    /// it at the header level; this test catches it at the byte level.
    #[test]
    fn truncated_proto_body_is_invalid_proving_content_length_must_be_removed() {
        // Use a realistic Namespace response similar to what kubectl create namespace returns.
        let json_str = r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"smoke-test","resourceVersion":"1","creationTimestamp":null},"spec":{"finalizers":["kubernetes"]},"status":{"phase":"Active"}}"#;
        let json_bytes = json_str.as_bytes();
        let json_len = json_bytes.len();

        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let proto_bytes = encode_proto_response(&val);

        // 1. Proto body must be larger than JSON (magic prefix + envelope overhead).
        assert!(
            proto_bytes.len() > json_len,
            "proto body ({} bytes) must be larger than JSON ({} bytes); \
             if equal, Content-Length mismatch cannot occur",
            proto_bytes.len(),
            json_len
        );

        // 2. Truncating to JSON size produces a body that fails to decode as a k8s proto envelope.
        //    This is exactly what kubectl sees when Content-Length = json_len is honoured: it reads
        //    json_len bytes of the proto stream, landing in the middle of an encoded field, and the
        //    Go proto decoder reports "illegal wireType" when the next byte's low 3 bits are 6.
        let truncated = &proto_bytes[..json_len];
        assert!(
            crate::proto::decode_k8s_proto_envelope(truncated).is_none(),
            "truncated proto body (first json_len bytes) must not decode as a valid k8s envelope; \
             this proves the Content-Length mismatch corrupts the response"
        );

        // 3. The full proto body must decode correctly — removing Content-Length lets the client
        //    read all bytes and succeed.
        let envelope = crate::proto::decode_k8s_proto_envelope(&proto_bytes)
            .expect("full proto body must decode as a valid k8s envelope");
        let recovered: serde_json::Value =
            serde_json::from_slice(&envelope.raw).expect("envelope raw field must be valid JSON");
        assert_eq!(
            recovered["metadata"]["name"], "smoke-test",
            "name must survive the proto round-trip"
        );
    }

    /// The encoder function directly: encode_proto_response must produce a valid k8s
    /// protobuf envelope whose raw field (field 2) contains the original JSON bytes.
    ///
    /// This tests the encoder in isolation — if this test fails the middleware test would
    /// also fail, but having both makes root-cause analysis faster.
    #[test]
    fn encode_proto_response_produces_valid_envelope() {
        let val = serde_json::json!({
            "apiVersion": "v1",
            "kind": "CSINode",
            "metadata": { "name": "worker-1" }
        });

        let encoded = encode_proto_response(&val);

        // Must start with k8s magic.
        assert_eq!(
            &encoded[..4],
            &[0x6b, 0x38, 0x73, 0x00],
            "encoded bytes must start with k8s proto magic"
        );

        // Must be decodable as a k8s protobuf envelope.
        let envelope = crate::proto::decode_k8s_proto_envelope(&encoded)
            .expect("encode_proto_response must produce a decodable k8s envelope");

        // The raw field must contain the JSON.
        let recovered: serde_json::Value =
            serde_json::from_slice(&envelope.raw).expect("raw field must be valid JSON");
        assert_eq!(recovered["kind"], "CSINode");
        assert_eq!(recovered["metadata"]["name"], "worker-1");

        // contentType must be "application/json" so client-go uses the JSON decoder.
        assert_eq!(
            envelope.content_type, "application/json",
            "contentType field must be 'application/json'"
        );
    }

    /// POST/PUT/PATCH responses must NOT be re-encoded as proto even when the client sends
    /// Accept: application/vnd.kubernetes.protobuf.
    ///
    /// This is the primary regression fix for `kubectl create namespace smoke-test` failing with
    /// "proto: illegal wireType 6" in CI. When kubectl sends POST /api/v1/namespaces with
    /// Accept: protobuf and gets back a proto Unknown envelope with contentType=application/json,
    /// client-go's protobuf decoder does not reliably honour the contentType field: it may try to
    /// decode the raw JSON bytes as a typed proto message. The byte 'n' (0x6E) from "name" in
    /// the JSON is read as a proto tag with wire type 6, producing the illegal wireType error.
    ///
    /// Since the Accept header includes "application/json" as a fallback, the server is allowed
    /// to respond with JSON for write operations. kubectl will use its JSON decoder, which succeeds.
    #[tokio::test]
    async fn post_response_not_re_encoded_as_proto() {
        let namespace_json =
            r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"smoke-test"}}"#;
        let svc = FixedService {
            status: StatusCode::CREATED,
            content_type: "application/json",
            body: namespace_json,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/namespaces")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        // Content-Type must remain application/json — POST must NOT be re-encoded as proto.
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "POST response must not be re-encoded as proto even with proto Accept header; \
             client-go ignores contentType=application/json inside Unknown envelope for write ops"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "POST response body must not start with k8s proto magic"
        );
        assert_eq!(
            resp_body.as_ref(),
            namespace_json.as_bytes(),
            "POST response body must be the original JSON unchanged"
        );
    }

    /// PUT responses must NOT be re-encoded as proto (same reason as POST).
    #[tokio::test]
    async fn put_response_not_re_encoded_as_proto() {
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/api/v1/nodes/my-node")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/json", "PUT response must remain JSON");

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "PUT response body must not start with k8s proto magic"
        );
    }

    /// Node GET responses must NOT be re-encoded as proto even when the client sends
    /// Accept: application/vnd.kubernetes.protobuf.
    ///
    /// This is the regression test for the kubelet CI failure: "ci-node did not reach
    /// Ready=True within 120s / proto: illegal wireType 7". When the kubelet reads its own
    /// node status (GET /api/v1/nodes/ci-node?timeout=10s), client-go's typed proto decoder
    /// does not reliably honour the contentType=application/json field inside the Unknown
    /// envelope. It tries to decode Unknown.raw as a typed proto Node message, encounters JSON
    /// bytes (e.g. '/' in a CIDR or 'o' in "conditions") whose low 3 bits are 0b111 = wireType
    /// 7, and rejects the response with "proto: illegal wireType 7".
    ///
    /// Since Accept includes "application/json" as a fallback, returning JSON is legal per HTTP
    /// content negotiation and the kubelet's JSON decoder handles it correctly.
    #[tokio::test]
    async fn node_response_not_re_encoded_as_proto() {
        let node_json = r#"{"apiVersion":"v1","kind":"Node","metadata":{"name":"ci-node","uid":"abc-123","resourceVersion":"5"},"status":{"conditions":[{"type":"Ready","status":"True","lastHeartbeatTime":"2026-05-21T00:00:00Z","lastTransitionTime":"2026-05-21T00:00:00Z","reason":"KubeletReady","message":"kubelet is posting ready status"}],"addresses":[{"type":"InternalIP","address":"192.168.1.1"}]}}"#;
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: node_json,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        // Simulate kubelet: GET /api/v1/nodes/ci-node?timeout=10s with proto Accept.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/nodes/ci-node?timeout=10s")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        // Content-Type must remain application/json — Node must NOT be re-encoded as proto.
        // Re-encoding would cause "proto: illegal wireType 7" in the kubelet's Go proto decoder,
        // preventing the node from reaching Ready=True.
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "Node response must not be re-encoded as proto: client-go ignores \
             contentType=application/json inside Unknown envelope for typed Node messages, \
             causing wireType 7 errors when JSON bytes are mis-read as proto field tags"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "Node response body must not start with k8s proto magic"
        );
        assert_eq!(
            resp_body.as_ref(),
            node_json.as_bytes(),
            "Node response body must be the original JSON unchanged"
        );
    }

    /// NodeList responses must also NOT be re-encoded as proto.
    /// Same root cause as Node: client-go's typed proto decoder mis-reads JSON bytes.
    #[tokio::test]
    async fn node_list_response_not_re_encoded_as_proto() {
        let node_list_json = r#"{"apiVersion":"v1","kind":"NodeList","metadata":{"resourceVersion":"10"},"items":[{"apiVersion":"v1","kind":"Node","metadata":{"name":"ci-node"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}"#;
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: node_list_json,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let resp = layer_svc.call(proto_accept_request()).await.unwrap();

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "NodeList must not be re-encoded as proto"
        );

        let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "NodeList body must not start with k8s proto magic"
        );
    }

    /// Discovery responses (APIVersions, APIGroupList, APIResourceList) must NOT be re-encoded
    /// as proto even when the client sends Accept: protobuf.
    ///
    /// client-go 1.36+ sends Accept: application/vnd.kubernetes.protobuf for discovery
    /// requests but its discovery decoder path expects JSON, not the Unknown-envelope-with-JSON
    /// proto format. Re-encoding discovery responses as proto causes "proto: illegal wireType 6"
    /// in kubectl because the Go proto decoder encounters unexpected bytes when trying to decode
    /// the discovery response.
    #[tokio::test]
    async fn discovery_responses_not_re_encoded_as_proto() {
        for (kind, body) in [
            (
                "APIVersions",
                r#"{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}"#,
            ),
            (
                "APIGroupList",
                r#"{"kind":"APIGroupList","apiVersion":"v1","groups":[]}"#,
            ),
            (
                "APIResourceList",
                r#"{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[]}"#,
            ),
        ] {
            let svc = FixedService {
                status: StatusCode::OK,
                content_type: "application/json",
                body,
            };
            let mut layer_svc = ContentTypeLayer.layer(svc);

            let resp = layer_svc.call(proto_accept_request()).await.unwrap();

            // Content-Type must remain application/json — not converted to proto.
            let ct = resp
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(
                ct, "application/json",
                "discovery kind '{kind}' must not be re-encoded as proto even with proto Accept"
            );

            // Body must NOT start with the k8s proto magic.
            let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                !resp_body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
                "discovery kind '{kind}' body must not start with k8s proto magic"
            );
            // Body must be the original JSON.
            assert_eq!(
                resp_body.as_ref(),
                body.as_bytes(),
                "discovery kind '{kind}' body must be the original JSON unchanged"
            );
        }
    }

    /// Watch streams (Transfer-Encoding: chunked) must NOT be buffered or re-encoded as proto.
    ///
    /// This middleware never buffers a response body — there is no re-encoding path left
    /// to buffer for — so a chunked watch stream, which never ends while the connection
    /// is open, can never be deadlocked by a `to_bytes` call here.
    ///
    /// This is the regression for the pod lifecycle smoke test failure: the kubelet's
    /// node watch (`GET /api/v1/nodes?fieldSelector=metadata.name=ci-node&watch=true`)
    /// was being intercepted and buffered, so the kubelet never received any watch events,
    /// its local node cache remained empty, and it never ran any pods.
    #[tokio::test]
    async fn watch_stream_not_buffered_or_re_encoded() {
        // Simulate the watch handler: chunked transfer encoding, application/json.
        #[derive(Clone)]
        struct ChunkedService;
        impl Service<Request<Body>> for ChunkedService {
            type Response = Response<Body>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: Request<Body>) -> Self::Future {
                Box::pin(async move {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header("transfer-encoding", "chunked")
                        .body(Body::from(
                            r#"{"type":"ADDED","object":{"kind":"Node","apiVersion":"v1","metadata":{"name":"ci-node"}}}"#,
                        ))
                        .unwrap())
                })
            }
        }
        let mut layer_svc = ContentTypeLayer.layer(ChunkedService);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/nodes?fieldSelector=metadata.name%3Dci-node&watch=true")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        // Must remain application/json — not converted to proto.
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "chunked watch stream must not be re-encoded as proto: buffering an \
             infinite stream deadlocks the response"
        );

        // Transfer-Encoding header must be preserved.
        let te = resp
            .headers()
            .get("transfer-encoding")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            te, "chunked",
            "watch stream transfer-encoding must be preserved"
        );

        // Body must be the original NDJSON, not a proto envelope.
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !body_bytes.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
            "watch stream body must not start with k8s proto magic"
        );
    }

    /// OpenAPI endpoints must pass through with Content-Type: application/json unchanged,
    /// even when the client sends Accept: application/vnd.kubernetes.protobuf.
    ///
    /// If the ContentTypeLayer were to change the Content-Type on /openapi/v2 or /openapi/v3
    /// responses, kubectl would receive an unexpected Content-Type and report:
    ///   "the server was unable to respond with a content type that the client supports"
    /// aborting resource validation and breaking `kubectl create` / `kubectl apply`.
    ///
    /// This test fails on revert: if the openapi path exclusion is removed from
    /// ContentTypeLayer, the middleware enters its collection path and may interfere
    /// with the Content-Type header set by the openapi handlers.
    #[tokio::test]
    async fn openapi_paths_pass_through_content_type_unchanged() {
        let openapi_v2_body = r#"{"swagger":"2.0","info":{"title":"u7s","version":"v1"},"paths":{},"definitions":{}}"#;
        let openapi_v3_body = r#"{"paths":{}}"#;

        for (uri, body) in [
            ("/openapi/v2", openapi_v2_body),
            ("/openapi/v3", openapi_v3_body),
        ] {
            let svc = FixedService {
                status: StatusCode::OK,
                content_type: "application/json",
                body,
            };
            let mut layer_svc = ContentTypeLayer.layer(svc);

            // Simulate kubectl sending the standard k8s proto Accept header on an openapi
            // endpoint — this happens when kubectl probes discovery endpoints before creating
            // resources.
            let req = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header(
                    "accept",
                    "application/vnd.kubernetes.protobuf, application/json",
                )
                .body(Body::empty())
                .unwrap();

            let resp = layer_svc.call(req).await.unwrap();

            let ct = resp
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(
                ct, "application/json",
                "{uri} must return Content-Type: application/json even when client sends \
                 proto Accept — wrong Content-Type causes kubectl to report 'unable to respond \
                 with a content type that the client supports'"
            );

            let resp_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                resp_body.as_ref(),
                body.as_bytes(),
                "{uri} body must be unchanged — ContentTypeLayer must not modify openapi responses"
            );
        }
    }

    fn captured_log(buf: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    /// The access log must carry `user_agent`, `latency_ms` and `request_id` on the plain
    /// GET/JSON path, and the same `request_id` must be echoed back as `x-request-id` — an
    /// operator correlating a slow/erroring client report against server logs needs both the
    /// client identity (user_agent) and a way to line up a specific client-visible response
    /// with the exact log line that produced it (request_id).
    #[tokio::test]
    async fn access_log_carries_user_agent_latency_and_correlatable_request_id() {
        crate::test_utils::tracing_capture::install_global_test_subscriber();
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = crate::test_utils::tracing_capture::TestBufferGuard::new(buf.clone());

        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/my-namespace")
            .header("accept", "application/json")
            .header("user-agent", "kubectl/v1.34.0 (darwin/arm64)")
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        let request_id_header = resp
            .headers()
            .get("x-request-id")
            .expect(
                "response must carry x-request-id so a client can correlate its own \
                     request against the server's access log",
            )
            .to_str()
            .unwrap()
            .to_string();

        let log = captured_log(&buf);
        assert!(
            log.contains("kubectl/v1.34.0"),
            "access log must record the client's user_agent so operators can tell which \
             client made a request; log was: {log}"
        );
        assert!(
            log.contains("latency_ms"),
            "access log must record request latency — this was explicitly required so \
             operators can spot slow requests; log was: {log}"
        );
        assert!(
            log.contains(&request_id_header),
            "the request_id logged server-side must match the x-request-id echoed to the \
             client, otherwise a client-reported request_id can't be found in the logs; \
             log was: {log}"
        );
    }

    /// The access log must never contain the Authorization header value — logging a bearer
    /// token would leak credentials into log storage/shippers that operators and support staff
    /// can read, effectively handing out impersonation access to anyone with log access.
    #[tokio::test]
    async fn access_log_never_leaks_authorization_header_value() {
        crate::test_utils::tracing_capture::install_global_test_subscriber();
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = crate::test_utils::tracing_capture::TestBufferGuard::new(buf.clone());

        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: SAMPLE_JSON,
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/namespaces/my-namespace")
            .header("accept", "application/json")
            .header("authorization", "Bearer super-secret-token-value")
            .body(Body::empty())
            .unwrap();

        layer_svc.call(req).await.unwrap();

        let log = captured_log(&buf);
        assert!(
            !log.contains("super-secret-token-value"),
            "access log must never contain the bearer token value — this would leak \
             credentials to anyone with log access; log was: {log}"
        );
        assert!(
            !log.to_lowercase().contains("bearer"),
            "access log must not echo the Authorization scheme/value at all; log was: {log}"
        );
    }

    /// The access log above logs `user_agent` verbatim via `%user_agent` Display formatting,
    /// with no escaping performed by this crate. That is only safe because a header value
    /// containing CR/LF can never reach `req.headers()` in the first place: hyper/axum build
    /// every incoming header value through `http::HeaderValue`'s own byte validation, which
    /// this test exercises directly. If that upstream contract ever weakened (e.g. a
    /// validation-bypassing construction path were introduced), a client could send
    /// `User-Agent: real-agent\r\nfake-log-line: injected` and split/forge lines in the
    /// structured access log or inject ANSI/terminal escapes into an operator's terminal.
    #[test]
    fn header_value_rejects_embedded_crlf_so_user_agent_cannot_forge_access_log_lines() {
        assert!(
            HeaderValue::from_str("Mozilla/5.0 \r\nfake-log-line: injected").is_err(),
            "http::HeaderValue::from_str must reject header values containing CR/LF — this is \
             the sole reason logging user_agent verbatim in the access log is safe from \
             newline-log-injection and ANSI-terminal-escape-injection; if the http crate ever \
             accepted CR/LF here, this control would silently fail"
        );
    }

    /// Every branch of the middleware (openapi passthrough, non-GET, proto-eligible GET) must
    /// log the same field set — a request that happens to take a different internal code path
    /// must not silently disappear from correlation-by-user_agent/request_id tooling.
    #[tokio::test]
    async fn access_log_field_set_is_consistent_across_all_branches() {
        crate::test_utils::tracing_capture::install_global_test_subscriber();
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = crate::test_utils::tracing_capture::TestBufferGuard::new(buf.clone());

        // openapi passthrough branch
        let svc = FixedService {
            status: StatusCode::OK,
            content_type: "application/json",
            body: "{}",
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/openapi/v2")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .header("user-agent", "openapi-client/1.0")
            .body(Body::empty())
            .unwrap();
        layer_svc.call(req).await.unwrap();

        // non-GET branch
        let svc = FixedService {
            status: StatusCode::CREATED,
            content_type: "application/json",
            body: "{}",
        };
        let mut layer_svc = ContentTypeLayer.layer(svc);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/namespaces")
            .header(
                "accept",
                "application/vnd.kubernetes.protobuf, application/json",
            )
            .header("user-agent", "post-client/1.0")
            .body(Body::empty())
            .unwrap();
        layer_svc.call(req).await.unwrap();

        let log = captured_log(&buf);
        for needle in ["openapi-client/1.0", "post-client/1.0"] {
            assert!(
                log.contains(needle),
                "user_agent must be logged for every branch (openapi passthrough and non-GET), \
                 not just the default GET/JSON path — otherwise the access log is inconsistent \
                 depending on which internal branch a request takes; log was: {log}"
            );
        }
        let request_id_occurrences = log.matches("request_id").count();
        assert_eq!(
            request_id_occurrences, 2,
            "expected exactly one access-log line per request (2 requests made), each \
             carrying request_id — extra or missing lines mean the consolidation to a single \
             log point regressed; log was: {log}"
        );
    }

    /// A chunked watch response must come out of ContentTypeLayer with its header set
    /// completely untouched, including no added `x-request-id`.
    ///
    /// A watch's `Body` is a long-lived stream already wired to a broadcast receiver that
    /// was subscribed before this middleware ever ran (see `SqliteStore::watch`) — by the
    /// time headers reach this layer, "the response" is an in-progress kubelet/controller
    /// watch connection, not a finished value. The access-log header injection introduced
    /// alongside the request_id feature must honour that rule. If this regresses, kubelet
    /// and controller watches pick up a header mutation on every open that pre-040855f1 never
    /// performed, which is one of the two concrete structural risks flagged by the conformance
    /// bisection that isolated the access-log commit as the sole differentiator between a
    /// clean 446/446 pass and repeated multi-spec failures.
    #[tokio::test]
    async fn chunked_watch_response_headers_are_not_mutated_by_access_log() {
        #[derive(Clone)]
        struct ChunkedService;
        impl Service<Request<Body>> for ChunkedService {
            type Response = Response<Body>;
            type Error = std::convert::Infallible;
            type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Self::Error>> + Send>>;
            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn call(&mut self, _req: Request<Body>) -> Self::Future {
                Box::pin(async move {
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .header("transfer-encoding", "chunked")
                        .body(Body::from(
                            r#"{"type":"ADDED","object":{"kind":"Pod","apiVersion":"v1","metadata":{"name":"p"}}}"#,
                        ))
                        .unwrap())
                })
            }
        }
        let mut layer_svc = ContentTypeLayer.layer(ChunkedService);
        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/pods?watch=true")
            .header("accept", "application/json")
            .header("user-agent", "kubelet/v1.34.0")
            .body(Body::empty())
            .unwrap();

        let resp = layer_svc.call(req).await.unwrap();

        assert!(
            resp.headers().get("x-request-id").is_none(),
            "a chunked watch response must not gain an x-request-id header: the body is a \
             live stream already subscribed to the store's broadcast channel before this \
             middleware ran, so this response is not a finished value the way every other \
             response class is — headers must pass through exactly as the handler set them"
        );
        assert_eq!(
            resp.headers().get("transfer-encoding").unwrap(),
            "chunked",
            "transfer-encoding must be preserved unchanged on a watch response"
        );
    }

    // ---- negotiated_response / encoders() dispatch tests -------------------

    /// Every hot-path kind registered in `encoders()` must produce a protobuf-encoded
    /// response (correct Content-Type header + k8s magic-prefix bytes) when the client asks
    /// for it. A kind missing from this list (or whose encoder panics/returns garbage) is
    /// exactly the "silently substitutes JSON instead of honoring Accept: protobuf" spec-
    /// compliance gap this test exists to close.
    #[tokio::test]
    async fn negotiated_response_returns_protobuf_for_every_registered_hot_path_kind() {
        for (kind, api_version) in [
            ("Pod", "v1"),
            ("PodList", "v1"),
            ("Service", "v1"),
            ("ServiceList", "v1"),
            ("Node", "v1"),
            ("NodeList", "v1"),
            ("Endpoints", "v1"),
            ("EndpointsList", "v1"),
            ("Event", "v1"),
            ("EventList", "v1"),
            ("EndpointSlice", "discovery.k8s.io/v1"),
            ("EndpointSliceList", "discovery.k8s.io/v1"),
        ] {
            let obj = serde_json::json!({ "kind": kind, "apiVersion": api_version });
            let resp = negotiated_response("application/vnd.kubernetes.protobuf", obj);

            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/vnd.kubernetes.protobuf",
                "{kind}: Content-Type must be the k8s protobuf media type"
            );
            let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap_or_else(|e| panic!("{kind}: {e}"));
            assert!(
                body.starts_with(&[0x6b, 0x38, 0x73, 0x00]),
                "{kind}: response body must start with the k8s protobuf magic prefix"
            );
        }
    }

    /// `events.k8s.io/v1.Event`/`EventList` share the exact `kind` string "Event"/"EventList"
    /// with the legacy core `/api/v1` Event/EventList this dispatch table also serves, but the
    /// two are unrelated proto messages with different field numbers entirely. Before this fix,
    /// `encoders()` was keyed by `kind` alone, so an `events.k8s.io/v1` Event LIST with a
    /// protobuf Accept header was encoded using the core `v1.Event` proto schema — bytes a real
    /// client-go `EventsV1` typed client cannot parse, failing with "proto: wrong wireType = 2
    /// for field Nanos" (the exact live failure behind `[sig-instrumentation] Events API should
    /// delete a collection of events`). Since `events.k8s.io/v1.Event`/`EventList` have no
    /// registered encoder of their own, they must fall back to JSON, not silently borrow the
    /// core Event encoder.
    #[tokio::test]
    async fn negotiated_response_does_not_confuse_events_k8s_io_event_with_core_v1_event() {
        for kind in ["Event", "EventList"] {
            let obj = serde_json::json!({ "kind": kind, "apiVersion": "events.k8s.io/v1" });
            let resp = negotiated_response("application/vnd.kubernetes.protobuf", obj.clone());

            let ct = resp
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap();
            assert_eq!(
                ct, "application/json",
                "events.k8s.io/v1 {kind} has no registered encoder and must fall back to JSON, \
                 not be silently mis-encoded as the unrelated core/v1 {kind} proto message"
            );
        }
    }

    /// A kind with no registered encoder (every kind outside the bead's scoped hot-path list)
    /// must still get a valid response: plain JSON, exactly as if the client had not asked
    /// for protobuf at all. This is the fallback contract every one of the ~92 non-migrated
    /// `axum::Json` call sites implicitly relies on.
    #[tokio::test]
    async fn negotiated_response_falls_back_to_json_for_kind_without_encoder() {
        let obj = serde_json::json!({ "kind": "ConfigMap", "apiVersion": "v1", "data": {} });
        let resp = negotiated_response("application/vnd.kubernetes.protobuf", obj.clone());

        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            ct, "application/json",
            "a kind without a registered encoder must fall back to JSON, not error or hang"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let recovered: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            recovered, obj,
            "fallback body must be the original JSON, unchanged"
        );
    }

    /// A client that never asked for protobuf must never receive it, even for a kind that
    /// does have a registered encoder — Accept negotiation, not "can we", decides the format.
    #[tokio::test]
    async fn negotiated_response_falls_back_to_json_when_accept_does_not_request_protobuf() {
        let obj = serde_json::json!({ "kind": "Pod", "apiVersion": "v1" });
        let resp = negotiated_response("application/json", obj);

        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "application/json");
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.starts_with(&[0x6b, 0x38, 0x73, 0x00]));
    }
}
