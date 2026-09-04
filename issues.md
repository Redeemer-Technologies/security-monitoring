# Controller Branch Audit Issues

Audit target: the full `controllers` working tree compared with `master`, evaluated against the local Rock 17.8.1 checkout in `G:\RockBase\17_8`.

The controller feature is read-only and does not automatically change REST permissions. However, the issues below should be addressed before treating the audit results as authoritative or deploying the generated package directly over Rock 17.8.

## Branch-specific issues

### 1. [P1] `RockUiRestActionCatalog.cs` is untracked

`net.redeemertech.Security.Blocks/Blocks/RockUiRestActionCatalog.cs` is referenced by the Blocks project and used by `RestActionSecurityList`, but Git currently reports it as untracked.

Impact: the local build succeeds because the file exists in the working tree, but a Git-based CI or deployment build will fail unless the file is committed.

Suggested resolution: add the file to the branch along with the other currently uncommitted controller changes.

### 2. [P1] The Rock UI endpoint catalog is incomplete for Rock 17.8 — Resolved

Status: fixed for Rock 17.8 on September 3, 2026.

`RockUiRestActionCatalog` recognizes the legacy `api/blocks/action` route but misses core Rock 17.8 endpoints that are directly used by the Rock UI, including:

- `/api/v2/BlockActions/...`, used by Obsidian blocks.
- `/api/v2/checkin/...`, used by the check-in kiosk and simulator.
- `/api/Attendances`, used by Group Scheduler.
- `/api/userlogins/available`, used by Family Pre-Registration.
- Several WebForms endpoints such as group map and HTML content actions.

Impact: these actions are classified as "not needed by Rock." Deployment alone does not deny them, but applying the audit's implied remediation could break Obsidian, check-in, scheduling, registration, and other Rock functionality.

Relevant code: `net.redeemertech.Security.Blocks/Blocks/RockUiRestActionCatalog.cs`, especially the controller list and `PathPrefixes` collection.

Resolution: reconciled the catalog against the Rock 17.8.1 WebForms and Obsidian source. The catalog is now explicitly versioned for Rock 17.8 and includes the missing Obsidian block-action and check-in controllers, legacy check-in, scheduling, registration, block administration, group map, group placement, connection board, content slug, vCard, page-interaction, metric HTML, Lava rendering, account-picker, reminder, and username-availability endpoints. Generated group and connection-request deletes are method-scoped so unrelated controller actions are not classified as required.

Added `RockUiRestActionCatalogTests` with 99 passing cases covering the audited Rock 17.8 endpoints, normalization behavior, controller-level infrastructure matches, and negative boundary cases. This remains a manually maintained version catalog and must be re-audited when the target Rock version changes.

### 3. [P1] Request-count matching has potentially quadratic runtime — Resolved

Status: fixed on September 4, 2026.

In `RestActionSecurityList.AddRequestCounts`, every REST action without an exact literal match scans every distinct logged method/path. `IsRouteMatch` also reconstructs the same route-template regular expression for every candidate path.

Rock 17.8 contains roughly 3,000 REST actions. A busy installation can have tens of thousands of distinct API URLs in 30 days.

Impact: opening the REST Action Security block can perform millions of regular-expression operations and consume substantial web-server CPU. This work occurs after the DuckDB query, so the configured DuckDB timeout does not limit it.

Relevant code: `net.redeemertech.Security.Blocks/Blocks/RestActionSecurityList.cs`, lines 229-240 and 281-305 at the time of this audit.

Suggested resolution: compile each parameterized route once, then match the logged paths in a single pass or through an indexed structure.

Resolution: request counts are now processed in a single pass. Routes with literal paths use a direct dictionary lookup keyed by HTTP method and normalized path. Parameterized paths use an HTTP-method-specific literal-prefix trie with segment-count buckets before the remaining candidates are manually matched. Route templates are parsed once, each distinct logged request is processed once, and route matching no longer uses regular expressions.

### 4. [P2] Optional and catch-all routes are counted incorrectly — Resolved

Status: fixed on September 4, 2026.

`IsRouteMatch` converts every route placeholder to `[^/]+`. This means:

- Optional parameters still require a path segment.
- Catch-all parameters cannot consume multiple path segments.

Rock 17.8 contains optional routes such as `api/Badges/FamilyAttendance/{personId}/{monthCount}/{showAsIndividual?}`.

Impact: valid calls can be reported as zero or undercounted.

Relevant code: `net.redeemertech.Security.Blocks/Blocks/RestActionSecurityList.cs`, lines 298-305 at the time of this audit.

Suggested resolution: parse route tokens and emit different regular-expression fragments for required, optional, constrained, and catch-all parameters. Add route-matching unit tests.

Resolution: the manual matcher distinguishes required, optional, constrained, catch-all, and composite path segments. Query parameters are loaded from `cs-uri-query`, parsed separately from path segments, URL-decoded, and matched without depending on their order. Extra query parameters are allowed, while query parameters declared by a route template must match unless explicitly optional. Added focused matcher tests covering literal lookup, HTTP methods, prefix and segment-count filtering, optional and catch-all paths, `int` and `guid` constraints, composite segments, query-string behavior, and a production-scale synthetic workload.

### 5. [P2] Migration 009 creates no pages or block instances

Migration 009 registers the two new block types but does not create pages or add the blocks beneath the existing Rock Security page. Previous feature migrations in this plugin create their corresponding pages and blocks.

Impact: after installation, administrators will not see the feature unless they manually create pages and add both blocks.

Relevant code: `net.redeemertech.Security/Migration/009_RestControllerSecurityList.cs`.

Suggested resolution: if the feature is intended to appear automatically, add REST Controller Security and REST Action Security pages under the existing Rock Security page and place the corresponding blocks on them.

### 6. [P2] REST permissions are not necessarily the enforcement mechanism

The audit evaluates configured `RestController` and `RestAction` authorization rules, but Rock only enforces those rules when an endpoint uses the corresponding security filter/action. Some endpoints use `[Authenticate]` or custom authorization logic instead of `[Secured]`.

Impact: the block can imply that changing a REST action permission will secure an endpoint even when that permission is not consulted at runtime. Conversely, an endpoint protected by authentication or custom code may be reported as insecure.

Suggested resolution: incorporate the registered REST action metadata, especially its secured action/filter behavior, into the classification and clearly distinguish permission configuration from effective runtime exposure.

### 7. [P3] Blocks `app.config` contains apparent dependency downgrades

The working tree changes the following redirects relative to `master`:

- `System.Text.Json` from `6.0.0.10` to `6.0.0.9`.
- `Azure.Core` from `1.43.0.0` to `1.41.0.0`.

The Rock 17.8 compatibility build reported newer referenced versions, including Azure.Core `1.44.1.0`.

Impact: this does not currently affect the generated deployment ZIP because the project `app.config` is not packaged, but it creates misleading build configuration and compatibility warnings.

Suggested resolution: revert these unrelated changes or regenerate redirects against the intended target dependencies.

## Pre-existing Rock 17.8 deployment issues

These issues also exist on `master`, but they affect deployment of the controller branch against Rock 17.8.

### 8. [P1] The release package can overwrite Rock's framework assemblies with incompatible versions

`net.redeemertech.Security.Blocks/Build/PackageDistribution.ps1` explicitly adds the following shared assemblies to the release ZIP:

| Assembly | Package assembly version | Rock 17.8 assembly version |
| --- | --- | --- |
| `System.Buffers.dll` | `4.0.4.0` | `4.0.3.0` |
| `System.Memory.dll` | `4.0.2.0` | `4.0.1.2` |
| `System.Numerics.Vectors.dll` | `4.1.5.0` | `4.1.4.0` |
| `System.Runtime.CompilerServices.Unsafe.dll` | `6.0.1.0` | `6.0.0.0` |

Rock 17.8's `RockWeb/web.config` still redirects requests to the older Rock versions.

Impact: if deployment overlays the ZIP's `bin` directory onto RockWeb, it can replace Rock's copies while the application still requests the older strong-named assembly identities. This can cause application-wide `FileLoadException` failures.

Relevant code: `net.redeemertech.Security.Blocks/Build/PackageDistribution.ps1`, lines 97-107.

Suggested resolution: avoid shipping shared framework assemblies when Rock already supplies compatible versions, or implement a coordinated dependency and `web.config` binding-redirect upgrade. Validate the final deployed `bin` directory in an isolated Rock 17.8 site before production deployment.

### 9. [P2] An as-is source build against Rock 17.8 fails dependency resolution

Building the plugin directly against `RockBase/17_8` initially failed for two reasons:

1. Both plugin projects expect DuckDB packages under `Rock\packages`, but the Rock 17.8 checkout does not contain those package directories.
2. After supplying the DuckDB assemblies, `IISAlertBlockHttpModule.cs` required an explicit reference to `Microsoft.Owin`. Rock 17.8 added an OWIN overload to `WebRequestHelper.GetClientIpAddress`, and the compiler must resolve that type while compiling the existing call.

After temporarily supplying the DuckDB references and adding the OWIN reference in an isolated audit workspace, all plugin C# source—including the controller blocks—compiled successfully against Rock 17.8.1.

Impact: simply repointing the repository's `Rock` link to `RockBase/17_8` does not produce a successful build.

Suggested resolution: make DuckDB dependencies owned/restored by the plugin rather than assumed to exist in Rock's package tree, and add the Rock 17.8-compatible `Microsoft.Owin` reference.

## Missing verification coverage

No automated tests currently cover:

- Public and authenticated authorization classification.
- Explicit Deny All Users rule ordering.
- End-to-end request-count aggregation against production-scale IIS log data.
- Migration-created navigation/pages.
- Package compatibility with a stock Rock 17.8 `bin` directory and `web.config`.

## Verification already performed

- Debug and Release builds succeeded against Rock 17.0.
- A release ZIP was generated and contains both new Obsidian assets.
- Both Obsidian blocks bundled successfully using Rock 17.8 source.
- With temporary dependency corrections, all C# source compiled against Rock 17.8.1.
- The controller feature does not automatically alter REST permissions during migration or page load.
- The Rock 17.8 endpoint catalog has 99 passing regression cases and both plugin projects compile with the updated catalog.
- The indexed route matcher has 14 passing focused tests, including query-string handling and a 3,000-route/20,000-request synthetic workload, and the Blocks project compiles with the matcher integrated.
