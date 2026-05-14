using Rock.Data;

namespace net.redeemertech.Security.Model
{
    public class LavaApprovalSourceService : Service<LavaApprovalSource>
    {
        public LavaApprovalSourceService( RockContext context ) : base( context )
        {
        }
    }
}
