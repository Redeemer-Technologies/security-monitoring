using net.redeemertech.Security.Model;

using Rock;
using Rock.Utility;
using Rock.Web.HttpModules;

using System;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.Security.Principal;
using System.Threading;
using System.Web;

namespace net.redeemertech.Security
{
    [Description( "Returns a 404 for IP addresses currently blocked by IIS alerts." )]
    [Export( typeof( HttpModuleComponent ) )]
    [ExportMetadata( "ComponentName", "IIS Alert Block HTTP Module" )]
    [Rock.SystemGuid.EntityTypeGuid( "25fc7aa8-e1de-4f4f-9b53-9f25c5ce7c1b" )]
    public class IISAlertBlockHttpModule : HttpModuleComponent
    {
        internal const string SnapshotContextKey = "__RedeemertechIISRequestRuleSnapshot__";
        internal const string ConfigurationContextKey = "__RedeemertechIISRequestRuleConfiguration__";
        private const string PostAuthenticationProcessedContextKey = "__RedeemertechIISPostAuthenticationRuleProcessed__";
        private const string RequestBlockedContextKey = "__RedeemertechIISRequestBlocked__";
        private readonly IISAlertRequestRuleProcessor _requestRuleProcessor;
        private readonly IIISAlertExceptionLogger _exceptionLogger;

        public IISAlertBlockHttpModule()
            : this( IISAlertRuntime.RequestRuleProcessor, IISAlertRuntime.ExceptionLogger )
        {
        }

        internal IISAlertBlockHttpModule( IISAlertRequestRuleProcessor requestRuleProcessor, IIISAlertExceptionLogger exceptionLogger )
        {
            _requestRuleProcessor = requestRuleProcessor ?? throw new ArgumentNullException( nameof( requestRuleProcessor ) );
            _exceptionLogger = exceptionLogger ?? throw new ArgumentNullException( nameof( exceptionLogger ) );
        }

        public override bool IsActive => true;

        public override void Dispose()
        {
        }

        public override void Init( HttpApplication context )
        {
            context.BeginRequest += Application_BeginRequest;
            context.PostAuthenticateRequest += Application_PostAuthenticateRequest;
            context.EndRequest += Application_EndRequest;

            ExecuteFailOpen( "HTTP module initialization", () => IISAlertBlockedIpCache.EnsureLoaded() );
            ExecuteFailOpen( "HTTP module initialization", () => IISAlertRuleCache.EnsureLoaded() );
        }

        private void Application_BeginRequest( object sender, EventArgs e )
        {
            ExecuteFailOpen( "BeginRequest", () => Application_BeginRequestCore( sender ) );
        }

        private void Application_BeginRequestCore( object sender )
        {
            var application = sender as HttpApplication;
            var context = application?.Context;
            if ( context == null )
            {
                return;
            }

            var ipAddress = WebRequestHelper.GetClientIpAddress( new HttpRequestWrapper( context.Request ) );
            var isLocalRequest = IISAlertLocalRequestDetector.IsLocalRequest( context.Request, ipAddress );
            if ( !isLocalRequest && IISAlertBlockedIpCache.IsBlocked( ipAddress ) )
            {
                BlockRequest( context, application, 404, string.Empty );
                return;
            }

            var configuration = IISAlertRuleCache.Capture();
            context.Items[ConfigurationContextKey] = configuration;
            if ( !configuration.HasActiveRules )
            {
                return;
            }

            var snapshot = CreateSnapshot( context, ipAddress, configuration );
            snapshot.IsLocalRequest = isLocalRequest;
            context.Items[SnapshotContextKey] = snapshot;

            ProcessRules( context, configuration, snapshot, IISRequestRuleStage.PreAuthentication );
        }

        private void Application_PostAuthenticateRequest( object sender, EventArgs e )
        {
            ExecuteFailOpen( "PostAuthenticateRequest", () => Application_PostAuthenticateRequestCore( sender ) );
        }

        private void Application_PostAuthenticateRequestCore( object sender )
        {
            var application = sender as HttpApplication;
            var context = application?.Context;
            if ( context == null || IsRequestBlocked( context ) )
            {
                return;
            }

            var snapshot = context.Items[SnapshotContextKey] as IISRequestRuleSnapshot;
            var configuration = context.Items[ConfigurationContextKey] as IISAlertRuleConfiguration;
            if ( snapshot == null || configuration == null || IsApiRequest( context.Request ) )
            {
                return;
            }

            var blockResult = ProcessPostAuthenticationRules( context, configuration, snapshot, context.User ?? Thread.CurrentPrincipal, null, _requestRuleProcessor );
            if ( blockResult != null )
            {
                BlockRequest( context, application, blockResult.StatusCode, blockResult.Message );
            }
        }

        private void Application_EndRequest( object sender, EventArgs e )
        {
            ExecuteFailOpen( "EndRequest", () => Application_EndRequestCore( sender ) );
        }

        private void Application_EndRequestCore( object sender )
        {
            var application = sender as HttpApplication;
            var context = application?.Context;
            if ( context == null || IsRequestBlocked( context ) )
            {
                return;
            }

            var snapshot = context.Items[SnapshotContextKey] as IISRequestRuleSnapshot;
            var configuration = context.Items[ConfigurationContextKey] as IISAlertRuleConfiguration;
            if ( snapshot == null || configuration == null )
            {
                return;
            }

            AddIdentityValues( context.User ?? Thread.CurrentPrincipal, snapshot, configuration );
            snapshot.SetValue( IISRequestRuleField.ResponseStatusCode, context.Response.StatusCode );
            snapshot.SetValue( IISRequestRuleField.ResponseSubStatusCode, context.Response.SubStatusCode );
            snapshot.SetValue( IISRequestRuleField.ResponseContentType, context.Response.ContentType );
            snapshot.SetValue( IISRequestRuleField.DurationMilliseconds, Math.Max( 0, ( DateTime.UtcNow - snapshot.StartedDateTimeUtc ).TotalMilliseconds ) );
            foreach ( var headerName in configuration.RequiredResponseHeaderNames )
            {
                snapshot.SetResponseHeader( headerName, context.Response.Headers[headerName] );
            }

            ProcessRules( context, configuration, snapshot, IISRequestRuleStage.EndRequest );
        }

        internal static IISRequestRuleSnapshot CreateSnapshot( HttpContext context, string ipAddress, IISAlertRuleConfiguration configuration )
        {
            var request = context.Request;
            var snapshot = new IISRequestRuleSnapshot
            {
                StartedDateTimeUtc = DateTime.UtcNow,
                IsLocalRequest = IISAlertLocalRequestDetector.IsLocalRequest( request, ipAddress )
            };

            snapshot.SetValue( IISRequestRuleField.ClientIp, ipAddress );
            snapshot.SetValue( IISRequestRuleField.HttpMethod, request.HttpMethod );
            snapshot.SetValue( IISRequestRuleField.Host, request.Url?.Host ?? request.Headers["Host"] );
            snapshot.SetValue( IISRequestRuleField.Path, request.Path );
            snapshot.SetValue( IISRequestRuleField.RawUrl, request.RawUrl );
            snapshot.SetValue( IISRequestRuleField.QueryString, request.QueryString?.ToString() );
            snapshot.SetValue( IISRequestRuleField.UserAgent, request.UserAgent );
            // Preserve malformed referrers for rule evaluation without parsing untrusted input as a URI.
            snapshot.SetValue( IISRequestRuleField.Referrer, request.Headers["Referer"] );
            snapshot.SetValue( IISRequestRuleField.RequestContentType, request.ContentType );
            snapshot.SetValue( IISRequestRuleField.RequestContentLength, request.ContentLength );

            foreach ( var headerName in configuration.RequiredHeaderNames )
            {
                snapshot.SetHeader( headerName, request.Headers[headerName] );
            }

            return snapshot;
        }

        internal static void AddIdentityValues( IPrincipal principal, IISRequestRuleSnapshot snapshot, IISAlertRuleConfiguration configuration, Guid? personGuid = null )
        {
            if ( snapshot.IdentityResolved )
            {
                return;
            }

            var identity = principal?.Identity;
            var isAuthenticated = identity?.IsAuthenticated == true || personGuid.HasValue;
            var userName = identity?.IsAuthenticated == true ? identity.Name : string.Empty;

            if ( !personGuid.HasValue
                && isAuthenticated
                && ( configuration.HasSecurityRoleConditions || configuration.HasAccountLockoutRules ) )
            {
                Guid cachedPersonGuid;
                if ( IISAuthenticatedUserCache.TryGetPersonGuid( userName, out cachedPersonGuid ) )
                {
                    personGuid = cachedPersonGuid;
                }
            }

            var suppressAccountLockout = false;
            if ( isAuthenticated && configuration.HasAccountLockoutRules )
            {
                // An unresolved identity must fail open for account lockout. If it is resolved,
                // protect the built-in Rock Administrators role from automated lockout.
                suppressAccountLockout = !personGuid.HasValue
                    || IISAlertAccountProtection.IsRockAdministrator( personGuid.Value );
            }

            snapshot.SetIdentity( isAuthenticated, userName, personGuid, suppressAccountLockout );
        }

        private void ProcessRules( HttpContext context, IISAlertRuleConfiguration configuration, IISRequestRuleSnapshot snapshot, IISRequestRuleStage stage )
        {
            var blockResult = _requestRuleProcessor.Process( configuration, snapshot, stage );
            if ( blockResult != null )
            {
                BlockRequest( context, context.ApplicationInstance, blockResult.StatusCode, blockResult.Message );
            }
        }

        internal static IISRequestBlockResult ProcessPostAuthenticationRules(
            HttpContext context,
            IISAlertRuleConfiguration configuration,
            IISRequestRuleSnapshot snapshot,
            IPrincipal principal,
            Guid? personGuid,
            IISAlertRequestRuleProcessor requestRuleProcessor )
        {
            if ( context == null
                || configuration == null
                || snapshot == null
                || ( context.Items[PostAuthenticationProcessedContextKey] is bool && ( bool ) context.Items[PostAuthenticationProcessedContextKey] ) )
            {
                return null;
            }

            AddIdentityValues( principal, snapshot, configuration, personGuid );
            context.Items[PostAuthenticationProcessedContextKey] = true;
            return requestRuleProcessor.Process( configuration, snapshot, IISRequestRuleStage.PostAuthentication );
        }

        internal static bool IsApiRequest( HttpRequest request )
        {
            if ( request == null )
            {
                return false;
            }

            var path = request.AppRelativeCurrentExecutionFilePath ?? request.Path ?? string.Empty;
            return string.Equals( path, "~/api", StringComparison.OrdinalIgnoreCase )
                || path.StartsWith( "~/api/", StringComparison.OrdinalIgnoreCase )
                || string.Equals( path, "/api", StringComparison.OrdinalIgnoreCase )
                || path.StartsWith( "/api/", StringComparison.OrdinalIgnoreCase );
        }

        private static void BlockRequest( HttpContext context, HttpApplication application, int statusCode, string message )
        {
            MarkRequestBlocked( context );
            context.Response.Clear();
            context.Response.StatusCode = statusCode >= 400 && statusCode <= 599 ? statusCode : 403;
            context.Response.TrySkipIisCustomErrors = true;

            if ( !string.IsNullOrEmpty( message ) )
            {
                context.Response.ContentType = "text/plain; charset=utf-8";
                context.Response.Write( message );
            }

            application.CompleteRequest();
        }

        internal static void MarkRequestBlocked( HttpContext context )
        {
            if ( context != null )
            {
                context.Items[RequestBlockedContextKey] = true;
            }
        }

        private static bool IsRequestBlocked( HttpContext context )
        {
            return context.Items[RequestBlockedContextKey] is bool && ( bool ) context.Items[RequestBlockedContextKey];
        }

        private bool ExecuteFailOpen( string operation, Action action )
        {
            return ExecuteFailOpen( operation, action, _exceptionLogger );
        }

        internal static bool ExecuteFailOpen( string operation, Action action, IIISAlertExceptionLogger exceptionLogger )
        {
            try
            {
                action();
                return true;
            }
            catch ( Exception ex )
            {
                IISAlertFailureHandling.LogFailOpen( exceptionLogger, operation, ex );
                return false;
            }
        }
    }
}
