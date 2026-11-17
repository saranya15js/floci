package io.floci.aws.core.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.aws.config.EmulatorConfig;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Records every request and response as one line of JSON (JSONL) when {@code floci.request-log.enabled} is true
 * ({@code FLOCI_REQUEST_LOG_ENABLED=true}). Each line is appended to {@code floci.request-log.file}, by default
 * {@code ./floci-requests.jsonl}, and is a self-contained JSON object shaped like a HAR 1.2 {@code entry}
 * (request, response and timings) with the caller's access key id added. The file streams and tails cleanly, and a
 * partial write can only affect its last line.
 *
 * <p>Request capture runs pre-matching at priority 1000, ahead of every other Floci filter, such as
 * {@link AwsProtocolClaimFilter} (pre-matching, 6000) and {@link IamEnforcementFilter} (default priority), so a
 * request one of them aborts is still captured. Response filters run in reverse priority order, so this one runs last
 * on the way out and sees the final status and headers, including those {@link AwsRequestIdFilter} adds.
 *
 * <p>The log is opt-in debug tooling, so it never disturbs the response it observes: any failure on either leg is
 * logged at warn and swallowed.
 *
 * <p>Pre-matching runs on the Vert.x IO thread, where reading the JAX-RS entity stream is a blocking operation that
 * RESTEasy Reactive refuses with {@code BlockingNotAllowedException}. The request body is therefore buffered by
 * {@link RequestLogBodyFilter}, a post-matching filter that runs on the worker thread, and handed over on the request
 * context. A request no post-matching filter sees, one that matches no resource or that a pre-matching filter aborts,
 * is still recorded, without {@code postData}.
 */
@Provider
@PreMatching
@Priority(1000)
public class RequestLogFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger LOG = Logger.getLogger(RequestLogFilter.class);

    static final String CAPTURE_PROPERTY = "floci.request-log.capture";
    static final String BODY_PROPERTY = "floci.request-log.body";

    /** Stands in for a body {@link RequestLogBodyFilter} declined to buffer because of its size. */
    static final String TRUNCATED = "<floci: body not captured, too large>";

    /** Stands in for a body unreadable because the request was handled on the Vert.x IO thread. */
    static final String NOT_BUFFERED_IO_THREAD =
            "<floci: body not captured, request handled on the IO thread>";

    /** Stands in for a response body streamed to the client, which reading here would consume. */
    static final String STREAMED = "<floci: streamed body not captured>";

    /** Header and query values carrying replayable secrets are stored as this instead of the value. */
    static final String REDACTED = "<floci: redacted>";

    /** Bodies larger than this are not buffered, so a multi-gigabyte upload is never mirrored. */
    static final int MAX_BODY_BYTES = 256 * 1024;

    static final String DEFAULT_FILE = "./floci-requests.jsonl";
    private static final String HTTP_VERSION = "HTTP/1.1";

    private final ObjectMapper objectMapper;
    // jakarta.inject.Provider qualified inline: this file imports jakarta.ws.rs.ext.Provider,
    // the JAX-RS annotation, and the two types collide. Resolved lazily for the same reason as
    // AwsProtocolClaimFilter: JAX-RS providers are instantiated before runtime config mappings
    // exist.
    private final jakarta.inject.Provider<EmulatorConfig> configProvider;

    private final Object writeLock = new Object();

    @Inject
    public RequestLogFilter(ObjectMapper objectMapper, jakarta.inject.Provider<EmulatorConfig> configProvider) {
        this.objectMapper = objectMapper;
        this.configProvider = configProvider;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!enabled()) {
            return;
        }
        try {
            String url = redactUrl(ctx.getUriInfo().getRequestUri().toString());
            RequestCapture capture = new RequestCapture(
                    System.nanoTime(),
                    Instant.now(),
                    ctx.getMethod(),
                    url,
                    headerList(ctx.getHeaders()),
                    queryStringList(ctx),
                    mimeType(ctx.getMediaType()),
                    callerAccessKeyId(ctx));
            ctx.setProperty(CAPTURE_PROPERTY, capture);
        } catch (Exception e) {
            LOG.warnv(e, "Request log: could not capture request {0} {1}", ctx.getMethod(),
                    ctx.getUriInfo().getPath());
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        if (!enabled()) {
            return;
        }
        if (!(requestContext.getProperty(CAPTURE_PROPERTY) instanceof RequestCapture capture)) {
            return;
        }
        try {
            appendEntry(buildEntry(capture, requestBody(requestContext), responseContext));
        } catch (Exception e) {
            LOG.warnv(e, "Request log: could not record response for {0} {1}",
                    capture.method(), capture.url());
        }
    }

    private boolean enabled() {
        try {
            return configProvider.get().requestLog().enabled();
        } catch (RuntimeException e) {
            LOG.tracev(e, "Request log: configuration not resolvable yet");
            return false;
        }
    }

    /**
     * The body {@link RequestLogBodyFilter} buffered, or {@code null} when the request carried none and when no
     * post-matching filter ran for it at all.
     */
    private static String requestBody(ContainerRequestContext ctx) {
        return ctx.getProperty(BODY_PROPERTY) instanceof String body ? body : null;
    }

    private Map<String, Object> buildEntry(RequestCapture capture, String requestBody,
                                           ContainerResponseContext response) {
        long elapsedMs = Duration.ofNanos(System.nanoTime() - capture.startedNanos()).toMillis();
        ResponseBody responseBody = responseBody(response);

        Map<String, Object> request = new LinkedHashMap<>();
        request.put("method", capture.method());
        request.put("url", capture.url());
        request.put("httpVersion", HTTP_VERSION);
        request.put("cookies", List.of());
        request.put("headers", capture.headers());
        request.put("queryString", capture.queryString());
        request.put("headersSize", -1);
        request.put("bodySize", byteLength(requestBody));
        if (requestBody != null) {
            Map<String, Object> postData = new LinkedHashMap<>();
            postData.put("mimeType", capture.mimeType());
            postData.put("params", List.of());
            postData.put("text", requestBody);
            request.put("postData", postData);
        }

        Map<String, Object> content = new LinkedHashMap<>();
        content.put("size", responseBody.originalSize());
        content.put("mimeType", mimeType(response.getMediaType()));
        content.put("text", responseBody.text());
        if (responseBody.encoding() != null) {
            content.put("encoding", responseBody.encoding());
        }

        Map<String, Object> responseNode = new LinkedHashMap<>();
        responseNode.put("status", response.getStatus());
        responseNode.put("statusText", statusText(response));
        responseNode.put("httpVersion", HTTP_VERSION);
        responseNode.put("cookies", List.of());
        responseNode.put("headers", headerList(response.getStringHeaders()));
        responseNode.put("content", content);
        responseNode.put("redirectURL", "");
        responseNode.put("headersSize", -1);
        responseNode.put("bodySize", responseBody.originalSize());

        Map<String, Object> timings = new LinkedHashMap<>();
        timings.put("send", 0);
        timings.put("wait", elapsedMs);
        timings.put("receive", 0);

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("startedDateTime", DateTimeFormatter.ISO_OFFSET_DATE_TIME
                .format(capture.startedAt().atOffset(ZoneOffset.UTC)));
        entry.put("time", elapsedMs);
        if (capture.callerAccessKeyId() != null) {
            entry.put("callerAccessKeyId", capture.callerAccessKeyId());
        }
        entry.put("request", request);
        entry.put("response", responseNode);
        entry.put("cache", Map.of());
        entry.put("timings", timings);
        return entry;
    }

    /**
     * Appends the entry as one JSON line. Appending under a lock keeps concurrent requests from interleaving partial
     * lines, costs O(1) per request and leaves every earlier line untouched. Each line is a complete JSON object, so a
     * crash mid-write can only corrupt the final line.
     */
    private void appendEntry(Map<String, Object> entry) {
        synchronized (writeLock) {
            Path target = logFile();
            try {
                createOwnerOnly(target);
                Files.writeString(target, objectMapper.writeValueAsString(entry) + System.lineSeparator(),
                        StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE,
                        StandardOpenOption.APPEND);
            } catch (IOException | RuntimeException e) {
                LOG.warnv(e, "Request log: could not write {0}", target);
            }
        }
    }

    /**
     * Creates the log readable and writable by its owner alone where the file system supports POSIX permissions, since
     * request and response bodies, secrets included, are written to it as plain text. A file that already exists keeps
     * the permissions it has.
     */
    static void createOwnerOnly(Path target) throws IOException {
        if (Files.exists(target)) {
            return;
        }
        Path parent = target.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try {
            if (target.getFileSystem().supportedFileAttributeViews().contains("posix")) {
                Files.createFile(target, PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rw-------")));
            } else {
                Files.createFile(target);
            }
        } catch (FileAlreadyExistsException e) {
            // Another writer created it first; it keeps the permissions it was created with.
        }
    }

    private Path logFile() {
        String configured = configProvider.get().requestLog().file()
                .map(String::strip)
                .filter(path -> !path.isEmpty())
                .orElse(DEFAULT_FILE);
        return Path.of(configured);
    }

    private ResponseBody responseBody(ContainerResponseContext response) {
        return responseBody(response.getEntity());
    }

    /** The stored form of a response entity, which is never read when it streams to the client. */
    ResponseBody responseBody(Object entity) {
        return switch (entity) {
            case null -> ResponseBody.EMPTY;
            case String text -> ResponseBody.text(truncate(text));
            case byte[] bytes -> encodeBytes(bytes);
            case CharSequence text -> ResponseBody.text(truncate(text.toString()));
            // Reading these would consume or reopen what the client is about to receive; their size is unknown here.
            case InputStream ignored -> ResponseBody.STREAMED_BODY;
            case StreamingOutput ignored -> ResponseBody.STREAMED_BODY;
            case File ignored -> ResponseBody.STREAMED_BODY;
            case Path ignored -> ResponseBody.STREAMED_BODY;
            default -> ResponseBody.text(serialize(entity));
        };
    }

    /**
     * A {@code byte[]} response (CBOR, or any binary content) is stored base64 with {@code encoding=base64} and its
     * original byte count, rather than decoded as UTF-8: decoding mangles non-text bytes and makes the logged size
     * disagree with what the client received.
     */
    static ResponseBody encodeBytes(byte[] bytes) {
        int originalSize = bytes.length;
        byte[] capped = bytes.length <= MAX_BODY_BYTES
                ? bytes : Arrays.copyOf(bytes, MAX_BODY_BYTES);
        String base64 = Base64.getEncoder().encodeToString(capped);
        return new ResponseBody(base64, "base64", originalSize);
    }

    private String serialize(Object entity) {
        try {
            return truncate(objectMapper.writeValueAsString(entity));
        } catch (JsonProcessingException e) {
            LOG.tracev(e, "Request log: entity of type {0} is not serializable to JSON",
                    entity.getClass().getName());
            return truncate(String.valueOf(entity));
        }
    }

    private static String truncate(String body) {
        return body.length() <= MAX_BODY_BYTES ? body : body.substring(0, MAX_BODY_BYTES);
    }

    private static int byteLength(String body) {
        return body == null ? 0 : body.getBytes(StandardCharsets.UTF_8).length;
    }

    private static String statusText(ContainerResponseContext response) {
        Response.StatusType statusInfo = response.getStatusInfo();
        return statusInfo == null || statusInfo.getReasonPhrase() == null ? "" : statusInfo.getReasonPhrase();
    }

    private static String mimeType(MediaType mediaType) {
        return mediaType == null ? "" : mediaType.toString();
    }

    /**
     * Header names whose values are replayable secrets: the SigV4 signature and any session token. Redacted before
     * anything is written, so a reader of the log cannot replay a still-valid signed request. Matched
     * case-insensitively.
     */
    private static final Set<String> SECRET_HEADERS = Set.of(
            "authorization", "x-amz-security-token", "x-amz-content-sha256");

    /**
     * Query parameter names carrying replayable secrets on a presigned URL. The credential's access key id is captured
     * separately as {@code callerAccessKeyId}, as it is no secret, but the signature, the security token and the full
     * credential string are redacted here.
     */
    private static final Set<String> SECRET_QUERY_PARAMS = Set.of(
            "X-Amz-Signature", "X-Amz-Security-Token", "X-Amz-Credential");

    private static List<Map<String, String>> headerList(MultivaluedMap<String, String> headers) {
        List<Map<String, String>> result = new ArrayList<>();
        if (headers == null) {
            return result;
        }
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            boolean secret = SECRET_HEADERS.contains(header.getKey().toLowerCase(Locale.ROOT));
            for (String value : header.getValue()) {
                String stored = secret ? REDACTED : (value == null ? "" : value);
                result.add(Map.of("name", header.getKey(), "value", stored));
            }
        }
        return result;
    }

    private static List<Map<String, String>> queryStringList(ContainerRequestContext ctx) {
        MultivaluedMap<String, String> params = ctx.getUriInfo().getQueryParameters();
        List<Map<String, String>> result = new ArrayList<>();
        if (params == null) {
            return result;
        }
        for (Map.Entry<String, List<String>> param : params.entrySet()) {
            boolean secret = SECRET_QUERY_PARAMS.contains(param.getKey());
            for (String value : param.getValue()) {
                String stored = secret ? REDACTED : (value == null ? "" : value);
                result.add(Map.of("name", param.getKey(), "value", stored));
            }
        }
        return result;
    }

    /**
     * The request URL with any presigned-secret query parameters redacted, so the stored URL cannot be replayed as a
     * still-valid signed request. Other parameters are kept.
     */
    static String redactUrl(String url) {
        if (url == null) {
            return null;
        }
        String redacted = url;
        for (String param : SECRET_QUERY_PARAMS) {
            redacted = redacted.replaceAll("([?&]" + Pattern.quote(param) + "=)[^&]*", "$1" + REDACTED);
        }
        return redacted;
    }

    private static final Pattern CREDENTIAL_AKID = Pattern.compile("Credential=([^/]+)/");

    /**
     * The SigV4 access key id the request was signed with, which ties each line to the caller that made it. Read from
     * the {@code Authorization} header, or from the {@code X-Amz-Credential} query parameter of a presigned request;
     * {@code null} for an unsigned request. Terraform, CloudFormation and direct SDK or CLI calls all sign with it.
     */
    private static String callerAccessKeyId(ContainerRequestContext ctx) {
        String auth = ctx.getHeaderString("Authorization");
        if (auth != null) {
            Matcher matcher = CREDENTIAL_AKID.matcher(auth);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        String presigned = ctx.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
        if (presigned != null && !presigned.isEmpty()) {
            return presigned.split("/", 2)[0];
        }
        return null;
    }

    /**
     * A captured response body. {@code text} is the stored form (UTF-8 text, or base64 for binary), {@code encoding}
     * is {@code "base64"} for binary content and {@code null} for text, and {@code originalSize} is the byte count of
     * the body the client received, before any truncation to {@link #MAX_BODY_BYTES}, or -1 when it is not known.
     */
    record ResponseBody(String text, String encoding, int originalSize) {
        static final ResponseBody EMPTY = new ResponseBody("", null, 0);
        static final ResponseBody STREAMED_BODY = new ResponseBody(STREAMED, null, -1);

        static ResponseBody text(String value) {
            String stored = value == null ? "" : value;
            return new ResponseBody(stored, null, stored.getBytes(StandardCharsets.UTF_8).length);
        }
    }

    /**
     * The request leg of one entry, stashed on the request context so the response filter can complete it. The body
     * is not part of it: {@link RequestLogBodyFilter} buffers it later and hands it over under {@link #BODY_PROPERTY}.
     */
    record RequestCapture(long startedNanos,
                          Instant startedAt,
                          String method,
                          String url,
                          List<Map<String, String>> headers,
                          List<Map<String, String>> queryString,
                          String mimeType,
                          String callerAccessKeyId) {
    }
}
