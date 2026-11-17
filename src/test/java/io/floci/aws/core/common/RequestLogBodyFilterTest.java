package io.floci.aws.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link RequestLogBodyFilter}'s bounded body read: an
 * undeclared-length (chunked) body larger than the cap must not be buffered whole. The logged
 * text is the truncation marker, only the cap is held, and the resource still receives the
 * complete body via the reconstructed stream.
 */
class RequestLogBodyFilterTest {

    @Test
    void oversizedUndeclaredLengthBodyIsTruncatedButFullyReplayed() throws IOException {
        int total = RequestLogFilter.MAX_BODY_BYTES + 5000;
        byte[] full = new byte[total];
        for (int i = 0; i < total; i++) {
            full[i] = (byte) (i % 256);
        }

        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.hasEntity()).thenReturn(true);
        // Undeclared/chunked length: -1, so a length check alone would not catch it.
        when(ctx.getLength()).thenReturn(-1);
        when(ctx.getEntityStream()).thenReturn(new ByteArrayInputStream(full));

        ArgumentCaptor<InputStream> replaced = ArgumentCaptor.forClass(InputStream.class);

        String logged;
        logged = RequestLogBodyFilter.captureRequestBody(ctx, () -> true);

        // The log records only the truncation marker, never the multi-hundred-KB body.
        assertThat(logged, equalTo(RequestLogFilter.TRUNCATED));

        // The resource still gets the COMPLETE body back, byte-for-byte.
        verify(ctx).setEntityStream(replaced.capture());
        byte[] replayed = replaced.getValue().readAllBytes();
        assertThat(replayed.length, equalTo(total));
        assertThat(replayed, equalTo(full));
    }

    @Test
    void smallBodyIsCapturedAndReplayed() throws IOException {
        byte[] small = "Action=ListQueues&Version=2012-11-05".getBytes();
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.hasEntity()).thenReturn(true);
        when(ctx.getLength()).thenReturn(small.length);
        when(ctx.getEntityStream()).thenReturn(new ByteArrayInputStream(small));

        ArgumentCaptor<InputStream> replaced = ArgumentCaptor.forClass(InputStream.class);

        String logged;
        logged = RequestLogBodyFilter.captureRequestBody(ctx, () -> true);

        assertThat(logged, equalTo(new String(small)));
        verify(ctx).setEntityStream(replaced.capture());
        assertThat(replaced.getValue().readAllBytes(), equalTo(small));
    }

    @Test
    void noEntityReturnsNull() throws IOException {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.hasEntity()).thenReturn(false);
        assertThat(RequestLogBodyFilter.captureRequestBody(ctx, () -> true), is(nullValue()));
    }

    @Test
    void aDeclaredLengthOverTheCapIsSkippedWithoutReading() throws IOException {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.hasEntity()).thenReturn(true);
        when(ctx.getLength()).thenReturn(RequestLogFilter.MAX_BODY_BYTES + 1);

        assertThat(RequestLogBodyFilter.captureRequestBody(ctx, () -> true), equalTo(RequestLogFilter.TRUNCATED));
        verify(ctx, never()).getEntityStream();
    }

    @Test
    void onTheIoThreadTheBodyIsLeftAlone() throws IOException {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.hasEntity()).thenReturn(true);
        when(ctx.getLength()).thenReturn(10);

        assertThat(RequestLogBodyFilter.captureRequestBody(ctx, () -> false),
                equalTo(RequestLogFilter.NOT_BUFFERED_IO_THREAD));
        verify(ctx, never()).getEntityStream();
        verify(ctx, never()).setEntityStream(any());
    }
}
