using net.redeemertech.Security.Model;

using Rock;
using Rock.Utility;
using Rock.Web.HttpModules;

using System;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.Globalization;
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
        private const string ResponseCounterContextKey = "__RedeemertechIISResponseByteCounter__";
        private const string RequestBlockedContextKey = "__RedeemertechIISRequestBlocked__";
        private const string EndRequestReadyContextKey = "__RedeemertechIISEndRequestRuleReady__";
        private const string EndRequestProcessedContextKey = "__RedeemertechIISEndRequestRuleProcessed__";

        public override bool IsActive => true;

        public override void Dispose()
        {
        }

        public override void Init( HttpApplication context )
        {
            IISAlertBlockedIpCache.EnsureLoaded();
            IISAlertRuleCache.EnsureLoaded();
            context.BeginRequest += Application_BeginRequest;
            context.PostAuthenticateRequest += Application_PostAuthenticateRequest;
            context.EndRequest += Application_EndRequest;
            context.PreSendRequestContent += Application_PreSendRequestContent;
        }

        private void Application_BeginRequest( object sender, EventArgs e )
        {
            var application = sender as HttpApplication;
            var context = application?.Context;
            if ( context == null )
            {
                return;
            }

            var ipAddress = WebRequestHelper.GetClientIpAddress( new HttpRequestWrapper( context.Request ) );
            if ( IISAlertBlockedIpCache.IsBlocked( ipAddress ) )
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
            context.Items[SnapshotContextKey] = snapshot;

            if ( configuration.RequiresResponseByteCounting && context.Response.Filter != null )
            {
                try
                {
                    var counter = new ResponseByteCountingStream( context.Response.Filter );
                    context.Response.Filter = counter;
                    context.Items[ResponseCounterContextKey] = counter;
                }
                catch ( HttpException )
                {
                    // Some response types do not support managed entity-body filtering.
                    // A Content-Length header can still provide the value at the end of the request.
                }
            }

            ProcessRules( context, configuration, snapshot, IISRequestRuleStage.PreAuthentication );
        }

        private void Application_PostAuthenticateRequest( object sender, EventArgs e )
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

            var blockResult = ProcessPostAuthenticationRules( context, configuration, snapshot, context.User ?? Thread.CurrentPrincipal );
            if ( blockResult != null )
            {
                BlockRequest( context, application, blockResult.StatusCode, blockResult.Message );
            }
        }

        private void Application_EndRequest( object sender, EventArgs e )
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

            ProcessRules( context, configuration, snapshot, IISRequestRuleStage.EndRequest, false );

            if ( configuration.RequiresResponseByteCounting )
            {
                // Buffered ASP.NET output may not pass through Response.Filter until the final
                // response flush, which happens after EndRequest. Mark the snapshot ready and
                // evaluate it from PreSendRequestContent after the byte counter has seen the body.
                context.Items[EndRequestReadyContextKey] = true;
                return;
            }
        }

        private void Application_PreSendRequestContent( object sender, EventArgs e )
        {
            var application = sender as HttpApplication;
            var context = application?.Context;
            if ( context != null && HttpRuntime.UsingIntegratedPipeline
                && !( context.Items[EndRequestReadyContextKey] is bool ) )
            {
                ( context.Items[ResponseCounterContextKey] as ResponseByteCountingStream )?.IgnoreNextFilteringPass();
            }

            if ( context == null
                || IsRequestBlocked( context )
                || !( context.Items[EndRequestReadyContextKey] is bool )
                || !( bool ) context.Items[EndRequestReadyContextKey]
                || ( context.Items[EndRequestProcessedContextKey] is bool && ( bool ) context.Items[EndRequestProcessedContextKey] ) )
            {
                return;
            }

            var snapshot = context.Items[SnapshotContextKey] as IISRequestRuleSnapshot;
            var configuration = context.Items[ConfigurationContextKey] as IISAlertRuleConfiguration;
            if ( snapshot == null || configuration == null )
            {
                return;
            }

            SetResponseBytes( context, snapshot );
            ProcessRules( context, configuration, snapshot, IISRequestRuleStage.EndRequest, true );
            context.Items[EndRequestProcessedContextKey] = true;
        }

        private static void SetResponseBytes( HttpContext context, IISRequestRuleSnapshot snapshot )
        {
            var counter = context.Items[ResponseCounterContextKey] as ResponseByteCountingStream;
            if ( counter != null )
            {
                snapshot.ResponseBytes = counter.BytesWritten;
                snapshot.ResponseBytesAvailable = true;
            }
            else
            {
                long contentLength;
                if ( long.TryParse( context.Response.Headers["Content-Length"], NumberStyles.Integer, CultureInfo.InvariantCulture, out contentLength ) )
                {
                    snapshot.ResponseBytes = contentLength;
                    snapshot.ResponseBytesAvailable = true;
                }
            }

            snapshot.SetValue( IISRequestRuleField.ResponseBytes, snapshot.ResponseBytesAvailable ? snapshot.ResponseBytes.ToString( CultureInfo.InvariantCulture ) : string.Empty );
        }

        internal static IISRequestRuleSnapshot CreateSnapshot( HttpContext context, string ipAddress )
        {
            return CreateSnapshot( context, ipAddress, IISAlertRuleCache.Capture() );
        }

        internal static IISRequestRuleSnapshot CreateSnapshot( HttpContext context, string ipAddress, IISAlertRuleConfiguration configuration )
        {
            var request = context.Request;
            var snapshot = new IISRequestRuleSnapshot
            {
                StartedDateTimeUtc = DateTime.UtcNow
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

        internal static void AddIdentityValues( IPrincipal principal, IISRequestRuleSnapshot snapshot, Guid? personGuid = null )
        {
            AddIdentityValues( principal, snapshot, IISAlertRuleCache.Capture(), personGuid );
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

            if ( !personGuid.HasValue && isAuthenticated && configuration.HasSecurityRoleConditions )
            {
                Guid cachedPersonGuid;
                if ( IISAuthenticatedUserCache.TryGetPersonGuid( userName, out cachedPersonGuid ) )
                {
                    personGuid = cachedPersonGuid;
                }
            }

            snapshot.SetIdentity( isAuthenticated, userName, personGuid );
        }

        private static void ProcessRules( HttpContext context, IISAlertRuleConfiguration configuration, IISRequestRuleSnapshot snapshot, IISRequestRuleStage stage, bool? requiresResponseBytes = null )
        {
            var blockResult = IISAlertRequestRuleProcessor.Process( configuration, snapshot, stage, requiresResponseBytes );
            if ( blockResult != null )
            {
                BlockRequest( context, context.ApplicationInstance, blockResult.StatusCode, blockResult.Message );
            }
        }

        internal static IISRequestBlockResult ProcessPostAuthenticationRules( HttpContext context, IISRequestRuleSnapshot snapshot, IPrincipal principal, Guid? personGuid = null )
        {
            var configuration = context?.Items[ConfigurationContextKey] as IISAlertRuleConfiguration ?? IISAlertRuleCache.Capture();
            return ProcessPostAuthenticationRules( context, configuration, snapshot, principal, personGuid );
        }

        internal static IISRequestBlockResult ProcessPostAuthenticationRules( HttpContext context, IISAlertRuleConfiguration configuration, IISRequestRuleSnapshot snapshot, IPrincipal principal, Guid? personGuid = null )
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
            return IISAlertRequestRuleProcessor.Process( configuration, snapshot, IISRequestRuleStage.PostAuthentication );
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
    }
}
