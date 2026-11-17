package io.floci.aws.core.common;

import io.quarkus.runtime.BlockingOperationControl;
import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.util.function.BooleanSupplier;

/**
 * Buffers the request body for {@link RequestLogFilter} and hands it over under {@link RequestLogFilter#BODY_PROPERTY}.
 *
 * <p>Separate from {@link RequestLogFilter} because of where each can run. {@link RequestLogFilter} is pre-matching,
 * which on RESTEasy Reactive means the Vert.x IO thread, and reading the JAX-RS entity stream there fails with
 * {@code BlockingNotAllowedException} instead of returning the body, which would drop the body of every AWS Query
 * POST. This filter is post-matching, so it runs after the dispatch to a worker thread that a blocking resource method
 * triggers, and the same read is legal. {@link io.floci.aws.services.iam.ResourceArnBuilder} and
 * {@link io.floci.aws.services.s3.S3HeaderSignatureFilter} read the entity stream from that same position.
 *
 * <p>Priority 1 puts it ahead of every other post-matching filter, so a request that {@link IamEnforcementFilter}
 * (default priority) aborts still has its body logged. It does nothing unless {@link RequestLogFilter} already opened
 * a capture for the request, which only happens while the request log is enabled.
 *
 * <p>Like the rest of the request log, it never disturbs the request it observes: the stream is put back as an
 * equivalent one for the resource method to read, and any failure is logged at warn and swallowed.
 */
@Provider
@Priority(1)
public class RequestLogBodyFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(RequestLogBodyFilter.class);

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!(ctx.getProperty(RequestLogFilter.CAPTURE_PROPERTY) instanceof RequestLogFilter.RequestCapture)) {
            return;
        }
        try {
            String body = captureRequestBody(ctx, BlockingOperationControl::isBlockingAllowed);
            if (body != null) {
                ctx.setProperty(RequestLogFilter.BODY_PROPERTY, body);
            }
        } catch (Exception e) {
            LOG.warnv(e, "Request log: could not capture request body for {0} {1}",
                    ctx.getMethod(), ctx.getUriInfo().getPath());
        }
    }

    /**
     * Buffers up to {@link RequestLogFilter#MAX_BODY_BYTES} of the request body for logging and
     * puts an equivalent stream back so the resource method still reads the whole body. Returns
     * {@code null} when there is no body, and a marker when the read would block on the IO thread
     * or when the body is skipped for its size.
     *
     * <p>A body whose declared {@code Content-Length} already exceeds the cap is skipped without
     * reading anything (the fast path): reading up to the cap of a large declared body would make
     * the filter wait on a slow client and hold a worker thread before the resource runs, and on a
     * blocking route (for example Bedrock {@code InvokeModel}) enough concurrent large requests
     * could exhaust the worker pool. Only a body of unknown length (chunked, {@code getLength() ==
     * -1}) is read, and then only bounded: {@code readNBytes} stops at the cap and the untouched
     * remainder is chained back via {@link SequenceInputStream}, so the resource still receives the
     * full body while the log never holds more than the cap.
     */
    static String captureRequestBody(ContainerRequestContext ctx, BooleanSupplier blockingAllowed) throws IOException {
        if (!ctx.hasEntity()) {
            return null;
        }
        // Fast path: a declared length over the cap is never read, so a large declared body cannot
        // make this filter wait on the client and occupy a worker thread.
        if (ctx.getLength() > RequestLogFilter.MAX_BODY_BYTES) {
            return RequestLogFilter.TRUNCATED;
        }
        if (!blockingAllowed.getAsBoolean()) {
            return RequestLogFilter.NOT_BUFFERED_IO_THREAD;
        }
        InputStream entityStream = ctx.getEntityStream();
        if (entityStream == null) {
            return null;
        }
        // Bounded read for an unknown or within-cap length; readNBytes stops at the cap.
        byte[] prefix = entityStream.readNBytes(RequestLogFilter.MAX_BODY_BYTES);
        // Peek one more byte to learn whether an unknown-length body exceeded the cap.
        int overflow = entityStream.read();
        boolean truncated = overflow != -1;
        if (truncated) {
            // Put the buffered prefix, the peeked byte, and the untouched remainder back so the
            // resource reads the complete body; we keep only the prefix in memory for the log.
            InputStream remainder = new SequenceInputStream(
                    new ByteArrayInputStream(new byte[] {(byte) overflow}), entityStream);
            ctx.setEntityStream(new SequenceInputStream(new ByteArrayInputStream(prefix), remainder));
            return RequestLogFilter.TRUNCATED;
        }
        ctx.setEntityStream(new ByteArrayInputStream(prefix));
        if (prefix.length == 0) {
            return null;
        }
        return new String(prefix, StandardCharsets.UTF_8);
    }
}
