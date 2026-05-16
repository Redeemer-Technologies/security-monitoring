using Rock;
using Rock.Data;
using Rock.Model;
using Rock.Security;
using Rock.Web.Cache;

using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.SqlClient;
using System.Linq;
using System.Text.RegularExpressions;

namespace net.redeemertech.Security
{
    public class LavaApprovalSourcePublicEvaluator
    {
        public bool? DetermineIsPublic( RockContext rockContext, string tableName, int rowId )
        {
            if ( tableName.Equals( "Block", StringComparison.OrdinalIgnoreCase ) )
            {
                return IsBlockPublic( rockContext, rowId );
            }

            if ( !tableName.Equals( "AttributeValue", StringComparison.OrdinalIgnoreCase ) )
            {
                return null;
            }

            var context = rockContext.Database.SqlQuery<AttributeValueEntityContext>( @"
                SELECT
                    [av].[EntityId],
                    [a].[EntityTypeId] AS [AttributeEntityTypeId]
                FROM [dbo].[AttributeValue] [av]
                INNER JOIN [dbo].[Attribute] [a] ON [a].[Id] = [av].[AttributeId]
                WHERE [av].[Id] = @AttributeValueId",
                new SqlParameter( "@AttributeValueId", rowId ) ).FirstOrDefault();

            if ( context == null || !context.EntityId.HasValue || !context.AttributeEntityTypeId.HasValue )
            {
                return null;
            }

            var blockEntityTypeId = EntityTypeCache.Get( typeof( Block ) )?.Id;
            if ( blockEntityTypeId.HasValue && context.AttributeEntityTypeId.Value == blockEntityTypeId.Value )
            {
                return IsBlockPublic( rockContext, context.EntityId.Value );
            }

            var workflowActionTypeEntityTypeId = EntityTypeCache.Get( typeof( WorkflowActionType ) )?.Id;
            if ( workflowActionTypeEntityTypeId.HasValue && context.AttributeEntityTypeId.Value == workflowActionTypeEntityTypeId.Value )
            {
                return IsWorkflowActionTypePublic( rockContext, context.EntityId.Value );
            }

            return null;
        }

        public bool ContainsShortcodeTag( string content, string tagName )
        {
            if ( content.IsNullOrWhiteSpace() || tagName.IsNullOrWhiteSpace() )
            {
                return false;
            }

            return Regex.IsMatch( content, @"\{\[\s*" + Regex.Escape( tagName.Trim() ) + @"(?=\s|,|\])", RegexOptions.IgnoreCase );
        }

        public List<string> GetReferencedShortcodes( string content, IEnumerable<string> tagNames )
        {
            if ( content.IsNullOrWhiteSpace() || tagNames == null )
            {
                return new List<string>();
            }

            return tagNames
                .Where( t => ContainsShortcodeTag( content, t ) )
                .Distinct( StringComparer.OrdinalIgnoreCase )
                .OrderBy( t => t )
                .ToList();
        }

        private bool? IsBlockPublic( RockContext rockContext, int blockId )
        {
            var block = new BlockService( rockContext ).Queryable()
                .Include( b => b.Page )
                .FirstOrDefault( b => b.Id == blockId );

            if ( block == null || block.Page == null )
            {
                return null;
            }

            return AllowsPublicView( block ) && AllowsPublicView( block.Page );
        }

        private bool? IsWorkflowActionTypePublic( RockContext rockContext, int workflowActionTypeId )
        {
            var workflowTypeId = rockContext.Database.SqlQuery<int?>( @"
                SELECT [wat].[WorkflowTypeId]
                FROM [dbo].[WorkflowActionType] [wa]
                INNER JOIN [dbo].[WorkflowActivityType] [wat] ON [wat].[Id] = [wa].[ActivityTypeId]
                WHERE [wa].[Id] = @WorkflowActionTypeId",
                new SqlParameter( "@WorkflowActionTypeId", workflowActionTypeId ) ).FirstOrDefault();

            if ( !workflowTypeId.HasValue )
            {
                return null;
            }

            var workflowType = WorkflowTypeCache.Get( workflowTypeId.Value );

            return workflowType == null ? ( bool? ) null : AllowsPublicView( workflowType );
        }

        private bool AllowsPublicView( ISecured secured )
        {
            return secured.IsAuthorized( Authorization.VIEW, null )
                || Authorization.Authorized( secured, Authorization.VIEW, SpecialRole.AllAuthenticatedUsers );
        }

        private class AttributeValueEntityContext
        {
            public int? EntityId { get; set; }

            public int? AttributeEntityTypeId { get; set; }
        }
    }
}
