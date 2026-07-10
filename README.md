# tinystruct-undertow-server

A tinystruct-based module to enable Undertow server support. It starts an embedded Undertow server with tinystruct routing capabilities.

## Features
- Embedded Undertow 2.3.12.Final (High-performance, non-blocking I/O server)
- Tinystruct-powered request routing via `/?q=...`
- Static file serving from project root
- Server-Sent Events (SSE) support (including MCP SSE)
- Simple CLI bootstrap with configurable server port and proxy settings

## Requirements
- Java 17+
- Maven 3.8+

## Build
```bash
mvnw clean package
```

Artifacts:
- `target/tinystruct-undertow-server-<version>-jar-with-dependencies.jar`
- Dependencies copied to `lib/` (via maven-dependency-plugin)

## Run
You can run via the provided dispatcher scripts (recommended) or manually with `java`.

### Using dispatcher scripts
The `bin/dispatcher` (Unix) and `bin/dispatcher.cmd` (Windows) scripts bootstrap tinystruct actions.

- Unix/macOS:
```bash
bin/dispatcher start --import org.tinystruct.system.UndertowServer --server-port 8080
```

- Windows (PowerShell or cmd):
```bat
bin\dispatcher.cmd start --import org.tinystruct.system.UndertowServer --server-port 8080
```

Flags you can pass through the CLI (examples):
- `--server-port 7777`
- `--http.proxyHost host --http.proxyPort 8080`
- `--https.proxyHost host --https.proxyPort 8443`

When the server starts, it attempts to open the default browser at `http://localhost:<port>`.

### Run manually with Java
After building the jar-with-dependencies:
```bash
java -cp target/tinystruct-undertow-server-1.0.0-jar-with-dependencies.jar;lib/* org.tinystruct.app.Application start
```
Note: On Unix-based shells, replace `;` with `:` in the classpath.

## How it works
- Entry point: `org.tinystruct.system.UndertowServer` (`start` action)
- Embedded Undertow is configured with a default handler for static assets and an HTTP handler (`DefaultHandler`)
  - Initializes tinystruct `ApplicationManager`
  - Routes requests using the `q` parameter (e.g., `/?q=say/Hello`) or serves a default page configured via settings
  - Supports SSE when `Accept: text/event-stream` is present

Core classes:
- `org.tinystruct.system.UndertowServer`
- `org.tinystruct.system.UndertowServer.DefaultHandler`
- `org.tinystruct.http.undertow.RequestBuilder`
- `org.tinystruct.http.undertow.ResponseBuilder`

## Configuration
Tinystruct `Settings` are read at startup. You can set these via your runtime environment or tinystruct configuration files:
- `default.file.encoding` (e.g., `UTF-8`)
- `language` (defaults to `zh_CN` unless overridden)
- `system.directory` (defaults to the current working directory)
- `default.url_rewrite` (`enabled` to use clean URLs; otherwise falls back to `/?q=`)
- `default.home.page` (default action when `q` is missing; e.g., `say/Welcome`)
- `default.error.page` (action to route errors; e.g., `error`)
- `default.error.process` (boolean; when false, forwards to `default.error.page`)
- `ssl.enabled` (boolean; toggles protocol in generated host URLs)

Proxy (optional via CLI context):
- `--http.proxyHost`, `--http.proxyPort`
- `--https.proxyHost`, `--https.proxyPort`

## Request routing
- Static files: served from the current working directory by the default handler.
- Dynamic actions: `/?q=<namespace>/<action>` handled by tinystruct. Example:
  - `http://localhost:8080/?q=say/Hello`
- Language override: `?lang=en_US` (applies if supported and different from current `language` setting)

## SSE (Server-Sent Events)
To initiate an SSE stream, send requests with `Accept: text/event-stream` and a `q` pointing to an action that supports streaming.

For MCP SSE, `q` must equal the MCP endpoint (see `MCPSpecification.Endpoints.SSE`). The server sets up the appropriate response headers and streams events.

## Development
- Source: `src/main/java`
- Tests: `src/test/java`

Useful Maven commands:
```bash
mvnw -q -DskipTests package
mvnw test
```

## License
Apache License 2.0. See `LICENSE-2.0.txt`.

## Coordinates
```xml
<dependency>
    <groupId>org.tinystruct</groupId>
    <artifactId>tinystruct-undertow-server</artifactId>
    <version>1.0.7</version>
</dependency>
```

## Support
- Website: `https://tinystruct.org`
- Repository SCM: `https://github.com/tinystruct/tinystruct`
