using Rock;
using Rock.Data;
using Rock.Model;
using Rock.Web.Cache;

using System;
using System.Linq;

namespace net.redeemertech.Security
{
    internal static class IISAlertAccountProtection
    {
        internal static bool IsRockAdministrator( Guid personGuid )
        {
            var administratorRole = RoleCache.Get( Rock.SystemGuid.Group.GROUP_ADMINISTRATORS.AsGuid() );
            if ( administratorRole == null )
            {
                throw new InvalidOperationException( "The built-in Rock Administrators role could not be loaded." );
            }

            return administratorRole.IsPersonInRole( personGuid );
        }

        internal static bool IsRockAdministrator( RockContext rockContext, int? personId )
        {
            if ( rockContext == null )
            {
                throw new ArgumentNullException( nameof( rockContext ) );
            }

            if ( !personId.HasValue )
            {
                return false;
            }

            var administratorRoleGuid = Rock.SystemGuid.Group.GROUP_ADMINISTRATORS.AsGuid();
            return new GroupMemberService( rockContext ).Queryable()
                .Any( member => member.PersonId == personId.Value
                    && member.Group.Guid == administratorRoleGuid
                    && member.Group.IsActive
                    && member.GroupMemberStatus == GroupMemberStatus.Active );
        }
    }
}
