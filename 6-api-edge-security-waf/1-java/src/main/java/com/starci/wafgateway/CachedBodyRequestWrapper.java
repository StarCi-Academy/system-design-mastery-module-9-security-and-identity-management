package com.starci.wafgateway;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;

// Buffers the request body so the WAF filter can inspect it AND the downstream
// controller can still read it. A servlet input stream is single-pass, so we
// cache the bytes once and hand out fresh streams over them.
public class CachedBodyRequestWrapper extends HttpServletRequestWrapper {

    private final byte[] cachedBody;

    public CachedBodyRequestWrapper(HttpServletRequest request, byte[] cachedBody) {
        super(request);
        this.cachedBody = cachedBody;
    }

    public byte[] getCachedBody() {
        return cachedBody;
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream stream = new ByteArrayInputStream(cachedBody);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return stream.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // No-op: synchronous reads only.
            }

            @Override
            public int read() throws IOException {
                return stream.read();
            }
        };
    }
}
