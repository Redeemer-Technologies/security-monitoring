using Rock.Utility;
using Rock.Web.HttpModules;

using System;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.Web;

namespace net.redeemertech.Security
{
    [Description( "Returns a 404 for IP addresses currently blocked by IIS alerts." )]
    [Export( typeof( HttpModuleComponent ) )]
    [ExportMetadata( "ComponentName", "IIS Alert Block HTTP Module" )]
    [Rock.SystemGuid.EntityTypeGuid( "25fc7aa8-e1de-4f4f-9b53-9f25c5ce7c1b" )]
    public class IISAlertBlockHttpModule : HttpModuleComponent
    {
        public override bool IsActive => true;

        public override void Dispose()
        {
        }

        public override void Init( HttpApplication context )
        {
            IISAlertBlockedIpCache.EnsureLoaded();
            context.BeginRequest += Application_BeginRequest;
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
            if ( !IISAlertBlockedIpCache.IsBlocked( ipAddress ) )
            {
                return;
            }

            context.Response.StatusCode = 404;
            context.Response.TrySkipIisCustomErrors = true;
            application.CompleteRequest();
        }
    }
}
