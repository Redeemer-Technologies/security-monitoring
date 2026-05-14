using Rock.Data;

namespace net.redeemertech.Security.Model
{
    public class LavaApprovalService : Service<LavaApproval>
    {
        public LavaApprovalService( RockContext context ) : base( context )
        {
        }
    }
}
