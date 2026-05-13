using Rock.Data;

namespace net.redeemertech.Security.Model
{
    public class IISAlertBlockedIpService : Service<IISAlertBlockedIp>
    {
        public IISAlertBlockedIpService( RockContext context ) : base( context )
        {
        }
    }
}
