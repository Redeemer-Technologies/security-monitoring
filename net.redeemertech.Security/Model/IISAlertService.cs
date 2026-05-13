using Rock.Data;

namespace net.redeemertech.Security.Model
{
    public class IISAlertService : Service<IISAlert>
    {
        public IISAlertService( RockContext context ) : base( context )
        {
        }
    }
}
