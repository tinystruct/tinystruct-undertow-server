/*******************************************************************************
 * Copyright  (c) 2013, 2025 James M. ZHOU
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.tinystruct.http;

import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import org.tinystruct.ApplicationException;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Tinystruct Response adapter for Undertow HTTP Server (no servlet APIs).
 */
public class UndertowResponse implements Response<HttpServerExchange, HttpServerExchange> {
    private final HttpServerExchange exchange;
    private final org.tinystruct.http.Headers headers = new org.tinystruct.http.Headers();
    private ResponseStatus status = ResponseStatus.OK;
    private Version version = Version.HTTP1_1;
    private boolean closed = false;
    private boolean headersSent = false;

    public UndertowResponse(HttpServerExchange exchange) {
        this.exchange = exchange;
        exchange.startBlocking();
    }

    public void setContentType(String contentType) {
        addHeader(Header.CONTENT_TYPE.name(), contentType);
    }

    @Override
    public void addHeader(String header, Object value) {
        exchange.getResponseHeaders().add(Headers.fromCache(header), String.valueOf(value));
        headers.add(new Header(header).set(value));
    }

    @Override
    public void sendRedirect(String url) throws ApplicationException {
        addHeader(Header.LOCATION.name(), url);
        setStatus(ResponseStatus.TEMPORARY_REDIRECT);
        try {
            exchange.setStatusCode(this.status.code());
            headersSent = true;
        } catch (Exception e) {
            throw new ApplicationException(e);
        }
        close();
    }

    @Override
    public void writeAndFlush(byte[] bytes) throws ApplicationException {
        if (!headersSent) {
            exchange.setStatusCode(this.status.code());
            headersSent = true;
        }

        if (bytes != null && bytes.length > 0) {
            exchange.getResponseSender().send(ByteBuffer.wrap(bytes));
        }
    }

    @Override
    public HttpServerExchange get() {
        return exchange;
    }

    @Override
    public void close() throws ApplicationException {
        if (closed) return;
        try {
            exchange.endExchange();
        } catch (Exception e) {
            // Already closed or in progress
        }
        closed = true;
    }

    @Override
    public ResponseStatus status() {
        return status;
    }

    @Override
    public Response<HttpServerExchange, HttpServerExchange> setStatus(ResponseStatus status) {
        this.status = status;
        return this;
    }

    @Override
    public org.tinystruct.http.Headers headers() {
        return headers;
    }

    @Override
    public Version version() {
        return version;
    }

    @Override
    public void setVersion(Version version) {
        this.version = version;
    }

    /**
     * Send response headers once with a known content length. Use -1 to keep default behavior.
     */
    public void sendHeaders(long contentLength) throws ApplicationException {
        if (headersSent) return;
        try {
            if (contentLength >= 0) {
                exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, contentLength);
            }
            exchange.setStatusCode(this.status.code());
            headersSent = true;
        } catch (Exception e) {
            throw new ApplicationException(e);
        }
    }

    public boolean isClosed() {
        return closed;
    }
}