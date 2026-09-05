# IIS response lifecycle regression test

Build the security project in Debug, then run `./net.redeemertech.Security.Tests/IISLifecycle/Run.ps1` from the repository root. The fixture requires IIS Express, .NET Framework 4.7.2+, and the Visual Studio 2022 C# compiler. Use `-Port` to change the default localhost port 18769.

The script creates a unique site under the ignored `TestResults` directory, compiles the harness against the built production assembly, starts IIS Express, and stops that process in a `finally` block. It preserves the event JSON and IIS logs for inspection.

The fixture invokes the actual production module event handlers and response counter. It bypasses Rock's database-backed component constructor and cache initialization, supplies one in-memory byte rule, and replaces the background queue with an execution recorder. It does not connect to a Rock database or send email. Unit tests separately cover API identity, configuration publication, cooldown, and injected action failures.

For buffered output, explicit flushes, unbuffered streaming, `CompleteRequest`, `Response.End`, an empty initial flush, and an empty response, the fixture checks both the delivered body length and the final measured bytes. An advancing test clock prevents cooldown from hiding duplicate evaluations; every case must produce exactly one byte-rule event.

This fixture caught an integrated-pipeline overcount: ASP.NET can pass native response buffers through the filter again after an explicit send notification. The module marks that replay pass so the counter forwards it without counting it twice. See Microsoft's [HttpWriter reference source](https://github.com/microsoft/referencesource/blob/main/System.Web/HttpWriter.cs), `FilterIntegrated`, for native-buffer filtering behavior.

The fixture verifies IIS Express integrated mode. It does not certify every production module combination, native compression or kernel caching behavior, or client disconnect timing. `ResponseBytes` measures the application body at this filter, not transport headers or compressed bytes on the network. Queued action delivery remains best-effort as described in [realtime-actions.md](../../realtime-actions.md).
