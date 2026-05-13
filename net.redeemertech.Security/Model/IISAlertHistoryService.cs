using Rock.Data;

namespace net.redeemertech.Security.Model
{
    public class IISAlertHistoryService : Service<IISAlertHistory>
    {
        public IISAlertHistoryService( RockContext context ) : base( context )
        {
        }
    }
}
