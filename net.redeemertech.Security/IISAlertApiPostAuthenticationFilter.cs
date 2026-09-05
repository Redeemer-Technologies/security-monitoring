using Rock.Model;
using Rock.Utility;

using System;
using System.Net;
using System.Net.Http;
using System.Security.Principal;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace net.redeemertech.Security
{
    /// <summary>
    /// Evaluates the logical post-authentication rule stage after Rock's Web API
    /// authentication filters have resolved API key, JWT, or OIDC credentials.
    /// </summary>
    internal sealed class IISAlertApiPostAuthenticationFilter : ActionFilterAttribute
    {
        private readonly IISAlertRequestRuleProcessor _requestRuleProcessor;
        private readonly IIISAlertExceptionLogger _exceptionLogger;

        public IISAlertApiPostAuthenticationFilter()
            : this( IISAlertRuntime.RequestRuleProcessor, IISAlertRuntime.ExceptionLogger )
        {
        }

        internal IISAlertApiPostAuthenticationFilter( IISAlertRequestRuleProcessor requestRuleProcessor, IIISAlertExceptionLogger exceptionLogger )
        {
            _requestRuleProcessor = requestRuleProcessor ?? throw new ArgumentNullException( nameof( requestRuleProcessor ) );
            _exceptionLogger = exceptionLogger ?? throw new ArgumentNullException( nameof( exceptionLogger ) );
        }

        public override void OnActionExecuting( HttpActionContext actionContext )
        {
            IISAlertBlockHttpModule.ExecuteFailOpen(
                "Web API post-authentication filter",
                () => OnActionExecutingCore( actionContext ),
                _exceptionLogger );
        }

        private void OnActionExecutingCore( HttpActionContext actionContext )
        {
            var context = HttpContext.Current;
            if ( context == null )
            {
                return;
            }

            var configuration = context.Items[IISAlertBlockHttpModule.ConfigurationContextKey] as IISAlertRuleConfiguration;
            if ( configuration == null )
            {
                configuration = IISAlertRuleCache.Capture();
                context.Items[IISAlertBlockHttpModule.ConfigurationContextKey] = configuration;
            }

            if ( !configuration.HasPostAuthenticationRules && !configuration.HasEndRequestRules )
            {
                return;
            }

            var snapshot = context.Items[IISAlertBlockHttpModule.SnapshotContextKey] as IISRequestRuleSnapshot;
            if ( snapshot == null )
            {
                var ipAddress = WebRequestHelper.GetClientIpAddress( new HttpRequestWrapper( context.Request ) );
                snapshot = IISAlertBlockHttpModule.CreateSnapshot( context, ipAddress, configuration );
                context.Items[IISAlertBlockHttpModule.SnapshotContextKey] = snapshot;
            }

            Guid? personGuid = null;
            object personValue;
            if ( actionContext.Request.Properties.TryGetValue( "Person", out personValue ) )
            {
                personGuid = ( personValue as Person )?.Guid;
            }

            IPrincipal principal = actionContext.Request.GetUserPrincipal()
                ?? actionContext.RequestContext?.Principal
                ?? Thread.CurrentPrincipal;
            var blockResult = IISAlertBlockHttpModule.ProcessPostAuthenticationRules(
                context,
                configuration,
                snapshot,
                principal,
                personGuid,
                _requestRuleProcessor );
            if ( blockResult == null )
            {
                return;
            }

            var statusCode = blockResult.StatusCode >= 400 && blockResult.StatusCode <= 599
                ? blockResult.StatusCode
                : 403;
            var response = new HttpResponseMessage( ( HttpStatusCode ) statusCode );
            if ( !string.IsNullOrEmpty( blockResult.Message ) )
            {
                response.Content = new StringContent( blockResult.Message, Encoding.UTF8, "text/plain" );
            }

            context.Response.TrySkipIisCustomErrors = true;
            IISAlertBlockHttpModule.MarkRequestBlocked( context );
            actionContext.Response = response;
        }
    }

    /// <summary>
    /// Registers the API filter after Rock has configured its global Web API pipeline.
    /// </summary>
    public sealed class IISAlertApiPostAuthenticationStartup : IRockStartup
    {
        private static int _isRegistered;

        public int StartupOrder => 0;

        public void OnStartup()
        {
            IISAlertBlockHttpModule.ExecuteFailOpen(
                "Web API filter registration",
                () =>
                {
                    if ( Interlocked.Exchange( ref _isRegistered, 1 ) == 0 )
                    {
                        try
                        {
                            GlobalConfiguration.Configuration.Filters.Add( new IISAlertApiPostAuthenticationFilter() );
                        }
                        catch
                        {
                            Interlocked.Exchange( ref _isRegistered, 0 );
                            throw;
                        }
                    }
                },
                IISAlertRuntime.ExceptionLogger );
        }
    }
}
