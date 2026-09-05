using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

using Rock.Model;
using Rock.Security;

namespace net.redeemertech.Security.Blocks.Blocks
{
    internal static class RestActionSecurityPolicy
    {
        // Controller types never change while the app domain is alive, and this is
        // called once per RestAction when the grid loads. Misses are cached too so
        // unknown controllers are not re-resolved on every row.
        private static readonly ConcurrentDictionary<string, Type> ControllerTypeCache =
            new ConcurrentDictionary<string, Type>( StringComparer.Ordinal );

        // SecuredAction metadata is null for both [Secured] and no attribute.
        // Inspect the same method identity that Rock uses to register endpoints.
        public static List<string> GetEnforcedActions( RestAction action )
        {
            var className = action.Controller?.ClassName;
            var controllerType = string.IsNullOrWhiteSpace( className )
                ? null
                : ControllerTypeCache.GetOrAdd( className, ResolveControllerType );

            if ( controllerType == null )
            {
                return new List<string>();
            }

            var method = controllerType.GetMethods().FirstOrDefault( candidate =>
            {
                Guid? methodGuid;
                var apiId = RestControllerService.GetApiId( candidate, action.Method, action.Controller.Name, out methodGuid );
                return ( methodGuid.HasValue && methodGuid.Value == action.Guid ) || apiId == action.ApiId;
            } );

            if ( method == null )
            {
                return new List<string>();
            }

            return method.GetCustomAttributes( true )
                .Concat( controllerType.GetCustomAttributes( true ) )
                .Where( attribute => IsSecuredAttribute( attribute.GetType() ) )
                .Select( attribute => attribute.GetType().GetProperty( "SecurityAction" )?.GetValue( attribute ) as string )
                .Select( securityAction => string.IsNullOrWhiteSpace( securityAction )
                    ? ( string.Equals( action.Method, "GET", StringComparison.OrdinalIgnoreCase ) ? Authorization.VIEW : Authorization.EDIT )
                    : securityAction )
                .Distinct( StringComparer.OrdinalIgnoreCase )
                .ToList();
        }

        // Rock.Reflection.FindType( typeof( object ), name ) enumerates every type in
        // every Rock assembly per call. Assembly.GetType is a direct lookup by full name.
        private static Type ResolveControllerType( string className )
        {
            foreach ( var assembly in Rock.Reflection.GetRockAndPluginAssemblies() )
            {
                Type type;
                try
                {
                    type = assembly.GetType( className, throwOnError: false );
                }
                catch ( Exception )
                {
                    continue;
                }

                if ( type != null )
                {
                    return type;
                }
            }

            return null;
        }

        private static bool IsSecuredAttribute( Type type )
        {
            for ( ; type != null; type = type.BaseType )
            {
                if ( type.FullName == "Rock.Rest.Filters.SecuredAttribute" )
                {
                    return true;
                }
            }

            return false;
        }

        public static bool ShouldSecure( bool isSecurable, bool isSecured )
        {
            return isSecurable && !isSecured;
        }

        public static List<Auth> PrependRules( int entityTypeId, int entityId, string securityAction,
            IEnumerable<int> allowedRoleIds, IEnumerable<Auth> existingRules )
        {
            var rules = allowedRoleIds.Select( roleId => new Auth
            {
                EntityTypeId = entityTypeId,
                EntityId = entityId,
                Action = securityAction,
                GroupId = roleId,
                SpecialRole = SpecialRole.None,
                AllowOrDeny = "A"
            } ).ToList();

            rules.Add( new Auth
            {
                EntityTypeId = entityTypeId,
                EntityId = entityId,
                Action = securityAction,
                SpecialRole = SpecialRole.AllUsers,
                AllowOrDeny = "D"
            } );

            var order = 0;
            foreach ( var rule in rules.Concat( existingRules.OrderBy( rule => rule.Order ).ThenBy( rule => rule.Id ) ) )
            {
                rule.Order = order++;
            }

            return rules;
        }
    }
}
