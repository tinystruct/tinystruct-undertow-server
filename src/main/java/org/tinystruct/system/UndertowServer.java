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
package org.tinystruct.system;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;
import io.undertow.util.HttpString;
import org.tinystruct.AbstractApplication;
import org.tinystruct.ApplicationContext;
import org.tinystruct.ApplicationException;
import org.tinystruct.application.Context;
import org.tinystruct.http.*;
import org.tinystruct.mcp.MCPPushManager;
import org.tinystruct.system.annotation.Action;
import org.tinystruct.system.annotation.Argument;
import org.tinystruct.system.util.StringUtilities;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Date;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.tinystruct.http.Constants.*;

public class UndertowServer extends AbstractApplication implements Bootstrap {
    private final Logger logger = Logger.getLogger(UndertowServer.class.getName());
    private Undertow server;
    private boolean started = false;
    private Settings settings;
    public static final String HTTP_DATE_FORMAT = "EEE, dd MMM yyyy HH:mm:ss zzz";
    public static final String HTTP_DATE_GMT_TIMEZONE = "GMT";
    public static final int HTTP_CACHE_SECONDS = 60;

    public UndertowServer() {
    }

    @Override
    public void init() {
        this.setTemplateRequired(false);
    }

    @Action(value = "start", description = "Start an Undertow HTTP server.", options = {
            @Argument(key = "server-port", description = "Server port"),
            @Argument(key = "server-host", description = "Server host (default: localhost)"),
            @Argument(key = "http.proxyHost", description = "Proxy host for http"),
            @Argument(key = "http.proxyPort", description = "Proxy port for http"),
            @Argument(key = "https.proxyHost", description = "Proxy host for https"),
            @Argument(key = "https.proxyPort", description = "Proxy port for https"),
            @Argument(key = "server-threads", description = "Number of IO threads (default: auto)")
    }, example = "bin/dispatcher start --import org.tinystruct.system.UndertowServer --server-port 8080", mode = Action.Mode.CLI)
    @Override
    public void start() throws ApplicationException {
        if (started) return;

        String charsetName = null;
        this.settings = new Settings();
        if (this.settings.get("default.file.encoding") != null)
            charsetName = this.settings.get("default.file.encoding");

        if (charsetName != null && !charsetName.trim().isEmpty())
            System.setProperty("file.encoding", charsetName);

        this.settings.set("language", "zh_CN");
        if (this.settings.get("system.directory") == null)
            this.settings.set("system.directory", System.getProperty("user.dir"));

        try {
            // Initialize the application manager with the configuration.
            ApplicationManager.init(this.settings);
        } catch (ApplicationException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
        }

        // The port that we should run on can be set into an environment variable
        // Look for that variable and default to 8080 if it isn't there.
        int webPort = 8080;
        String webHost = "localhost";
        int serverThreads = 0; // 0 means auto

        if (getContext() != null) {
            if (getContext().getAttribute("--http.proxyHost") != null && getContext().getAttribute("--http.proxyPort") != null) {
                System.setProperty("http.proxyHost", getContext().getAttribute("--http.proxyHost").toString());
                System.setProperty("http.proxyPort", getContext().getAttribute("--http.proxyPort").toString());
            }

            if (getContext().getAttribute("--https.proxyHost") != null && getContext().getAttribute("--https.proxyPort") != null) {
                System.setProperty("https.proxyHost", getContext().getAttribute("--https.proxyHost").toString());
                System.setProperty("https.proxyPort", getContext().getAttribute("--https.proxyPort").toString());
            }

            if (getContext().getAttribute("--server-port") != null) {
                webPort = Integer.parseInt(getContext().getAttribute("--server-port").toString());
            }

            if (getContext().getAttribute("--server-host") != null) {
                webHost = getContext().getAttribute("--server-host").toString();
            }

            if (getContext().getAttribute("--server-threads") != null) {
                serverThreads = Integer.parseInt(getContext().getAttribute("--server-threads").toString());
            }
        }

        System.out.println(ApplicationManager.call("--logo", null, Action.Mode.CLI));

        final long start = System.currentTimeMillis();

        try {
            // Create Undertow server builder
            Undertow.Builder builder = Undertow.builder()
                    .addHttpListener(webPort, webHost);

            // Set thread pool if specified
            if (serverThreads > 0) {
                builder.setIoThreads(serverThreads);
            }

            // Set up the HTTP handler
            builder.setHandler(new DefaultUndertowHandler(this.settings));

            // Build and start the server
            server = builder.build();
            server.start();
            this.started = true;

            logger.info("Undertow server (" + webHost + ":" + webPort + ") startup in " + (System.currentTimeMillis() - start) + " ms");

            // Open the default browser
            getContext().setAttribute("--url", "http://" + webHost + ":" + webPort);
            ApplicationManager.call("open", getContext(), Action.Mode.CLI);

            // Keep the server running
            logger.info("Server is running. Press Ctrl+C to stop.");

            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Shutting down Undertow server...");
                stop();
            }));

            // Keep the main thread alive
            while (started) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

        } catch (Exception e) {
            throw new ApplicationException("Failed to start Undertow server: " + e.getMessage(), e);
        }
    }

    @Override
    public void stop() {
        if (server != null && started) {
            logger.info("Stopping Undertow server...");
            try {
                server.stop();
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error stopping server", e);
            }
            started = false;
            logger.info("Undertow server stopped");
        }
    }

    @Action(value = "error", description = "Error page")
    public Object exceptionCaught(Request request, Response response) throws ApplicationException {
        Reforward reforward = new Reforward(request, response);
        this.setVariable("from", reforward.getFromURL());

        Session session = request.getSession();
        if (session.getAttribute("error") != null) {
            ApplicationException exception = (ApplicationException) session.getAttribute("error");

            String message = exception.getRootCause().getMessage();
            this.setVariable("exception.message", Objects.requireNonNullElse(message, "Unknown error"));

            StackTraceElement[] stackTrace = exception.getStackTrace();
            StringBuilder builder = new StringBuilder();
            builder.append(exception).append("\n");
            for (StackTraceElement stackTraceElement : stackTrace) {
                builder.append(stackTraceElement.toString()).append("\n");
            }
            logger.severe(builder.toString());

            return this.getVariable("exception.message").getValue().toString();
        } else {
            reforward.forward();
        }

        return "This request is forbidden!";
    }

    @Override
    public String version() {
        return "1.0.0";
    }

    /**
     * Undertow HTTP handler that integrates with TinyStruct framework
     */
    private class DefaultUndertowHandler implements HttpHandler {

        private final Settings settings;

        private DefaultUndertowHandler(Settings settings) {
            this.settings = settings;
        }

        @Override
        public void handleRequest(HttpServerExchange exchange) {
            try {
                // Handle CORS preflight (OPTIONS) requests up-front: these have no body.
                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod().toString())) {
                    // CORS preflight handling with configurability
                    String origin = exchange.getRequestHeaders().getFirst("Origin");
                    String acrMethod = exchange.getRequestHeaders().getFirst("Access-Control-Request-Method");
                    String acrHeaders = exchange.getRequestHeaders().getFirst("Access-Control-Request-Headers");

                    // Allow origins: prefer explicit setting, otherwise echo Origin or wildcard
                    String allowOrigin = settings.getOrDefault("cors.allowed.origins", origin != null ? origin : "*");
                    exchange.getResponseHeaders().put(new HttpString("Access-Control-Allow-Origin"), allowOrigin);
                    // Make responses vary by Origin when echoing it
                    if (origin != null) {
                        exchange.getResponseHeaders().put(new HttpString("Vary"), "Origin");
                    }

                    // Allow methods: prefer configured list, otherwise echo requested or use sensible defaults
                    String allowMethods = settings.getOrDefault("cors.allowed.methods", acrMethod != null ? acrMethod : "GET,POST,PUT,DELETE,OPTIONS");
                    exchange.getResponseHeaders().put(new HttpString("Access-Control-Allow-Methods"), allowMethods);

                    // Allow headers: prefer configured list, otherwise echo requested or common headers
                    String allowHeaders = settings.getOrDefault("cors.allowed.headers", acrHeaders != null ? acrHeaders : "Content-Type,Authorization");
                    exchange.getResponseHeaders().put(new HttpString("Access-Control-Allow-Headers"), allowHeaders);

                    // Allow credentials if explicitly enabled in settings
                    if ("true".equalsIgnoreCase(settings.get("cors.allow.credentials"))) {
                        exchange.getResponseHeaders().put(new HttpString("Access-Control-Allow-Credentials"), "true");
                    }

                    // Cache the preflight response for a configurable duration (seconds)
                    String maxAge = settings.getOrDefault("cors.preflight.maxage", "3600");
                    exchange.getResponseHeaders().put(new HttpString("Access-Control-Max-Age"), maxAge);

                    exchange.setStatusCode(200);
                    exchange.getResponseSender().send("");
                    return;
                }
                // Serve static files first
                if ("GET".equalsIgnoreCase(exchange.getRequestMethod().toString())) {
                    if (tryServeStatic(exchange)) {
                        return;
                    }
                }
                if (exchange.isInIoThread()) {
                    exchange.dispatch(this);
                    return;
                }
                // Create TinyStruct Request and Response wrappers
                UndertowRequest request = new UndertowRequest(exchange);
                UndertowResponse response = new UndertowResponse(exchange);

                // Set up context
                ApplicationContext context = new ApplicationContext();
                context.setId(request.getSession().getId());
                context.setAttribute(HTTP_REQUEST, request);
                context.setAttribute(HTTP_RESPONSE, response);

                // Process SSE first to ensure correct headers and long-lived connection
                if (isSSE(exchange)) {
                    handleSSE(request, response, context);
                    return;
                }

                // Process the request using TinyStruct's logic
                processRequest(request, response, context);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error processing request", e);
                try {
                    sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage());
                } catch (Exception ignored) {
                    // If we can't send an error, just log
                }
            }
        }

        private boolean isSSE(HttpServerExchange exchange) {
            String accept = exchange.getRequestHeaders().getFirst("Accept");
            return accept != null && accept.contains("text/event-stream");
        }

        private SSEPushManager getAppropriatePushManager(boolean isMCP) {
            return isMCP ? MCPPushManager.getInstance() : SSEPushManager.getInstance();
        }

        private void handleSSE(UndertowRequest request, UndertowResponse response, Context context) throws IOException, ApplicationException {
            // Set SSE headers
            response.addHeader(Header.CONTENT_TYPE.name(), "text/event-stream; charset=utf-8");
            response.addHeader(Header.CACHE_CONTROL.name(), "no-cache");
            response.addHeader(Header.CONNECTION.name(), "keep-alive");
            response.addHeader("X-Accel-Buffering", "no");

            String query = request.getParameter("q");
            boolean isMCP = false;
            if (query != null) {
                query = StringUtilities.htmlSpecialChars(query);
                if (query.equals(org.tinystruct.mcp.MCPSpecification.Endpoints.SSE)) {
                    isMCP = true;
                }

                Object call = ApplicationManager.call(query, context);
                String sessionId = context.getId();
                SSEPushManager pushManager = getAppropriatePushManager(isMCP);
                response.setStatus(ResponseStatus.OK);
                response.sendHeaders(-1);
                SSEClient client = pushManager.register(sessionId, response);

                if (call instanceof org.tinystruct.data.component.Builder) {
                    pushManager.push(sessionId, (org.tinystruct.data.component.Builder) call);
                } else if (call instanceof String) {
                    org.tinystruct.data.component.Builder builder = new org.tinystruct.data.component.Builder();
                    builder.parse((String) call);
                    pushManager.push(sessionId, builder);
                }

                if (client != null) {
                    try {
                        while (client.isActive()) {
                            Thread.sleep(1000);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new ApplicationException("Stream interrupted: " + e.getMessage(), e);
                    } catch (Exception e) {
                        throw new ApplicationException("Error in stream: " + e.getMessage(), e);
                    } finally {
                        client.close();
                        pushManager.remove(sessionId);
                    }
                }
            }
        }

        private boolean tryServeStatic(HttpServerExchange exchange) {
            try {
                String uri = exchange.getRequestURI();
                String path = sanitizeUri(uri);
                if (path == null) return false;

                String filepath = path;
                int q = path.indexOf("?");
                if (q >= 0) filepath = path.substring(0, q);

                java.io.File file = new java.io.File(filepath);
                if (!file.exists() || file.isHidden()) {
                    if (filepath.endsWith("/favicon.ico")) {
                        try (InputStream stream = Objects.requireNonNull(getClass().getResource("/favicon.ico")).openStream()) {
                            byte[] bytes = stream.readAllBytes();
                            exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "image/x-icon");
                            exchange.setStatusCode(200);
                            exchange.getResponseSender().send(ByteBuffer.wrap(bytes));
                            return true;
                        } catch (Exception ignore) {
                            return false;
                        }
                    }
                    return false;
                }

                if (!file.isFile()) return false;

                // If-Modified-Since support
                String ifModifiedSince = exchange.getRequestHeaders().getFirst("If-Modified-Since");
                if (ifModifiedSince != null && !ifModifiedSince.isEmpty()) {
                    java.text.SimpleDateFormat df = new java.text.SimpleDateFormat(HTTP_DATE_FORMAT, java.util.Locale.US);
                    df.setTimeZone(java.util.TimeZone.getTimeZone(HTTP_DATE_GMT_TIMEZONE));
                    java.util.Date ims = df.parse(ifModifiedSince);
                    long imsSeconds = ims.getTime() / 1000;
                    long fileSeconds = file.lastModified() / 1000;
                    if (imsSeconds == fileSeconds) {
                        setDateHeader(exchange);
                        exchange.setStatusCode(304);
                        return true;
                    }
                }

                // Content-Type
                String contentType = null;
                try {
                    jakarta.activation.MimetypesFileTypeMap mimeTypesMap = new jakarta.activation.MimetypesFileTypeMap(UndertowServer.class.getResourceAsStream("/META-INF/mime.types"));
                    contentType = mimeTypesMap.getContentType(file);
                } catch (Exception ignore) {
                }
                if (contentType == null || contentType.equalsIgnoreCase("application/octet-stream")) {
                    try {
                        contentType = java.nio.file.Files.probeContentType(Path.of(file.getName()));
                    } catch (IOException ignore) {
                    }
                }
                if (contentType == null) contentType = "application/octet-stream";

                // Cache headers
                setDateAndCacheHeaders(exchange, file);
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, contentType);
                exchange.getResponseHeaders().put(Headers.CONTENT_LENGTH, file.length());

                exchange.setStatusCode(200);
                try (InputStream in = new java.io.FileInputStream(file)) {
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        exchange.getResponseSender().send(ByteBuffer.wrap(buffer, 0, bytesRead));
                    }
                }
                return true;
            } catch (Exception e) {
                logger.log(Level.FINE, "Static serve miss: " + e.getMessage(), e);
                return false;
            }
        }

        private String sanitizeUri(String uri) throws java.io.UnsupportedEncodingException {
            String decoded = java.net.URLDecoder.decode(uri, java.nio.charset.StandardCharsets.UTF_8);
            if (decoded.isEmpty() || decoded.charAt(0) != '/') return null;
            if (decoded.length() > 255) throw new IllegalArgumentException("Input too long");
            decoded = decoded.replace('/', java.io.File.separatorChar);
            decoded = decoded.replace("..", "");
            if (decoded.contains(java.io.File.separator + '.') || decoded.contains('.' + java.io.File.separator) || decoded.charAt(0) == '.' || decoded.charAt(decoded.length() - 1) == '.')
                return null;
            return System.getProperty("user.dir") + java.io.File.separator + decoded;
        }

        private void setDateHeader(HttpServerExchange exchange) {
            java.text.SimpleDateFormat df = new java.text.SimpleDateFormat(HTTP_DATE_FORMAT, java.util.Locale.US);
            df.setTimeZone(java.util.TimeZone.getTimeZone(HTTP_DATE_GMT_TIMEZONE));
            java.util.Calendar time = new java.util.GregorianCalendar();
            exchange.getResponseHeaders().put(Headers.DATE, df.format(time.getTime()));
        }

        private void setDateAndCacheHeaders(HttpServerExchange exchange, java.io.File file) {
            java.text.SimpleDateFormat df = new java.text.SimpleDateFormat(HTTP_DATE_FORMAT, java.util.Locale.US);
            df.setTimeZone(java.util.TimeZone.getTimeZone(HTTP_DATE_GMT_TIMEZONE));
            java.util.Calendar time = new java.util.GregorianCalendar();
            exchange.getResponseHeaders().put(Headers.DATE, df.format(time.getTime()));
            time.add(java.util.Calendar.SECOND, HTTP_CACHE_SECONDS);
            exchange.getResponseHeaders().put(Headers.EXPIRES, df.format(time.getTime()));
            exchange.getResponseHeaders().put(Headers.CACHE_CONTROL, "private, max-age=" + HTTP_CACHE_SECONDS);
            exchange.getResponseHeaders().put(Headers.LAST_MODIFIED, df.format(new Date(file.lastModified())));
        }

        private void processRequest(UndertowRequest request, UndertowResponse response, Context context) throws IOException, ApplicationException {
            try {
                // Handle command line parameters first
                String[] parameterNames = request.parameterNames();
                for (String parameter : parameterNames) {
                    if (parameter.startsWith("--")) {
                        context.setAttribute(parameter, request.getParameter(parameter));
                    }
                }

                // Handle language parameter
                String lang = request.getParameter("lang");
                if (lang != null && !lang.trim().isEmpty()) {
                    String name = lang.replace('-', '_');
                    if (Language.support(name) && !lang.equalsIgnoreCase(this.settings.get("language"))) {
                        context.setAttribute(LANGUAGE, name);
                    }
                }

                // Set up URL prefix logic
                String url_prefix = "/";
                if (this.settings.get("default.url_rewrite") != null && !"enabled".equalsIgnoreCase(this.settings.get("default.url_rewrite"))) {
                    url_prefix = "/?q=";
                }

                // Handle hostname configuration
                String host = request.headers().get(Header.HOST).toString();
                String hostName;
                if ((hostName = this.settings.get("default.hostname")) != null) {
                    if (hostName.length() <= 3) {
                        hostName = host;
                    }
                } else {
                    hostName = host;
                }

                // Set up protocol
                String http_protocol = "http://";
                if (request.isSecure()) {
                    http_protocol = "https://";
                }

                // Set up context attributes
                context.setAttribute(HTTP_HOST, http_protocol + hostName + url_prefix);
                context.setAttribute(HTTP_REQUEST, request);
                context.setAttribute(HTTP_RESPONSE, response);

                // Ensure session cookie (JSESSIONID) is set
                boolean sessionCookieExists = false;
                for (Cookie cookie : request.cookies()) {
                    if (cookie.name().equalsIgnoreCase(Constants.JSESSIONID)) {
                        sessionCookieExists = true;
                        break;
                    }
                }
                if (!sessionCookieExists) {
                    Cookie cookie = new CookieImpl(Constants.JSESSIONID);
                    if (host.contains(":"))
                        cookie.setDomain(host.substring(0, host.indexOf(":")));
                    cookie.setValue(context.getId());
                    cookie.setHttpOnly(true);
                    cookie.setPath("/");
                    cookie.setMaxAge(-1);
                    response.addHeader(Header.SET_COOKIE.name(), cookie);
                }

                // Handle query
                String query = request.getParameter("q");
                if (query != null && query.length() > 1) {
                    Method method = request.method();
                    Action.Mode mode = Action.Mode.fromName(method.name());
                    handleRequest(query, context, response, mode);
                } else {
                    handleDefaultPage(context, response);
                }
            } catch (ApplicationException e) {
                logger.log(Level.SEVERE, "Error in request processing", e);
                response.setContentType("text/plain; charset=UTF-8");
                int status = e.getStatus();
                response.setStatus(ResponseStatus.valueOf(status));
                response.writeAndFlush("500 - Internal Server Error".getBytes("UTF-8"));
                response.close();
            }
        }

        private void handleRequest(String query, Context context, UndertowResponse response, Action.Mode mode) throws IOException, ApplicationException {
            query = StringUtilities.htmlSpecialChars(query);
            Object message = ApplicationManager.call(query, context, mode);
            byte[] bytes;
            if (message != null) {
                if (message instanceof byte[]) {
                    bytes = (byte[]) message;
                } else {
                    response.setContentType("text/html; charset=UTF-8");
                    bytes = String.valueOf(message).getBytes("UTF-8");
                }
            } else {
                response.setContentType("text/html; charset=UTF-8");
                bytes = "No response retrieved!".getBytes("UTF-8");
            }

            response.setStatus(ResponseStatus.OK);
            response.writeAndFlush(bytes);
            response.close();
        }

        private void handleDefaultPage(Context context, UndertowResponse response) throws ApplicationException {
            response.setContentType("text/html; charset=UTF-8");
            Object result = ApplicationManager.call(settings.getOrDefault("default.home.page", "say/Praise the Lord."), context, Action.Mode.HTTP_GET);
            if (!response.isClosed()) {
                try {
                    byte[] bytes = String.valueOf(result).getBytes("UTF-8");
                    response.setStatus(ResponseStatus.OK);
                    response.writeAndFlush(bytes);
                } catch (UnsupportedEncodingException e) {
                    throw new ApplicationException(e);
                } finally {
                    response.close();
                }
            }
        }

        private void sendErrorResponse(HttpServerExchange exchange, int statusCode, String message) {
            try {
                byte[] responseBytes = message.getBytes("UTF-8");
                exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain; charset=UTF-8");
                exchange.setStatusCode(statusCode);
                exchange.getResponseSender().send(ByteBuffer.wrap(responseBytes));
            } catch (Exception e) {
                logger.log(Level.WARNING, "Error sending error response", e);
            }
        }
    }
}

