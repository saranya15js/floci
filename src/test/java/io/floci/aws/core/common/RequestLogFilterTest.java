package io.floci.aws.core.common;

import io.floci.aws.core.common.RequestLogFilter.ResponseBody;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * {@link RequestLogFilter}'s helpers: binary and CBOR body encoding, presigned-secret URL redaction, streamed bodies
 * and the log file's permissions.
 */
class RequestLogFilterTest {

    // ---- encodeBytes: binary/CBOR bodies are base64 with the ORIGINAL size ----

    @Test
    void binaryBodyIsBase64WithOriginalSize() {
        byte[] cbor = new byte[] {(byte) 0xA1, 0x63, 0x66, 0x6F, 0x6F, (byte) 0xF6, 0x00, (byte) 0xFF};
        ResponseBody body = RequestLogFilter.encodeBytes(cbor);

        assertThat(body.encoding(), equalTo("base64"));
        assertThat(body.originalSize(), equalTo(cbor.length));
        // The stored text decodes back to the original bytes, lossless unlike a UTF-8 decode.
        assertThat(Base64.getDecoder().decode(body.text()), equalTo(cbor));
    }

    @Test
    void largeBinaryBodyReportsOriginalSizeButCapsStoredBytes() {
        byte[] big = new byte[RequestLogFilter.MAX_BODY_BYTES + 4096];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) (i % 256);
        }
        ResponseBody body = RequestLogFilter.encodeBytes(big);

        assertThat(body.encoding(), equalTo("base64"));
        // Size is the true original count, not the capped/encoded length.
        assertThat(body.originalSize(), equalTo(big.length));
        // Only up to the cap is actually stored (base64 of MAX_BODY_BYTES bytes).
        assertThat(Base64.getDecoder().decode(body.text()).length, is(RequestLogFilter.MAX_BODY_BYTES));
    }

    @Test
    void textBodyHasNoEncodingAndUtf8Size() {
        ResponseBody body = ResponseBody.text("<Response>ok</Response>");
        assertThat(body.encoding(), is(nullValue()));
        assertThat(body.originalSize(),
                equalTo("<Response>ok</Response>".getBytes(StandardCharsets.UTF_8).length));
    }

    // ---- redactUrl: presigned-secret query params are redacted in the stored URL ----

    @Test
    void presignedSecretsAreRedactedInUrl() {
        String url = "http://localhost:4566/bucket/key"
                + "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=AKID%2F20260928%2Fus-east-1%2Fs3%2Faws4_request"
                + "&X-Amz-Signature=deadbeefcafe"
                + "&X-Amz-Security-Token=SESSIONTOKEN"
                + "&partNumber=2";
        String redacted = RequestLogFilter.redactUrl(url);

        assertThat(redacted, notNullValue());
        assertThat(redacted.contains("deadbeefcafe"), is(false));
        assertThat(redacted.contains("SESSIONTOKEN"), is(false));
        assertThat(redacted.contains("AKID"), is(false));
        // Non-secret params survive.
        assertThat(redacted.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"), is(true));
        assertThat(redacted.contains("partNumber=2"), is(true));
    }

    @Test
    void urlWithoutSecretsIsUnchanged() {
        String url = "http://localhost:4566/?Action=ListQueues&Version=2012-11-05";
        assertThat(RequestLogFilter.redactUrl(url), equalTo(url));
    }

    @Test
    void nullUrlIsHandled() {
        assertThat(RequestLogFilter.redactUrl(null), is(nullValue()));
    }

    // ---- streamed bodies and the log file ----

    @Test
    void aStreamedBodyIsNeverReadAndItsSizeIsUnknown() {
        ByteArrayInputStream stream = new ByteArrayInputStream("object bytes".getBytes(StandardCharsets.UTF_8));
        ResponseBody body = new RequestLogFilter(null, null).responseBody(stream);

        assertThat(body.text(), equalTo(RequestLogFilter.STREAMED));
        assertThat(body.originalSize(), equalTo(-1));
        assertThat(stream.available(), equalTo(12));
    }

    @Test
    void theLogIsCreatedReadableByItsOwnerOnly(@TempDir Path dir) throws IOException {
        Assumptions.assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path log = dir.resolve("nested").resolve("requests.jsonl");

        RequestLogFilter.createOwnerOnly(log);

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(log)), equalTo("rw-------"));
    }

    @Test
    void anExistingLogKeepsItsPermissions(@TempDir Path dir) throws IOException {
        Assumptions.assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
        Path log = Files.createFile(dir.resolve("requests.jsonl"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r-----")));

        RequestLogFilter.createOwnerOnly(log);

        assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(log)), equalTo("rw-r-----"));
    }
}
