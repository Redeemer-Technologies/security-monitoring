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
            return DetermineIsPublic( rockContext, tableName, rowId, null );
        }

        public bool? DetermineIsPublic( RockContext rockContext, string tableName, int rowId, ISet<int> publicWorkflowEntryWorkflowTypeIds )
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
                return IsWorkflowActionTypePublic( rockContext, context.EntityId.Value, publicWorkflowEntryWorkflowTypeIds );
            }

            return null;
        }

        public HashSet<int> GetPublicWorkflowEntryWorkflowTypeIds( RockContext rockContext )
        {
            var workflowEntryBlocks = rockContext.Database.SqlQuery<WorkflowEntryBlockContext>( @"
                DECLARE @BlockEntityTypeId INT = (SELECT [Id] FROM [EntityType] WHERE [Name] = 'Rock.Model.Block')

                SELECT DISTINCT
                    [Block].[Id] AS [BlockId],
                    COALESCE(NULLIF([WorkflowTypeValue].[Value], ''), NULLIF([WorkflowTypeAttribute].[DefaultValue], '')) AS [WorkflowTypeGuid]
                FROM [Block]
                INNER JOIN [BlockType] ON [BlockType].[Id] = [Block].[BlockTypeId]
                LEFT JOIN [Attribute] [WorkflowTypeAttribute]
                    ON [WorkflowTypeAttribute].[EntityTypeId] = @BlockEntityTypeId
                    AND [WorkflowTypeAttribute].[EntityTypeQualifierColumn] = 'BlockTypeId'
                    AND [WorkflowTypeAttribute].[EntityTypeQualifierValue] = CONVERT(VARCHAR(10), [Block].[BlockTypeId])
                    AND [WorkflowTypeAttribute].[Key] = 'WorkflowType'
                LEFT JOIN [AttributeValue] [WorkflowTypeValue]
                    ON [WorkflowTypeValue].[AttributeId] = [WorkflowTypeAttribute].[Id]
                    AND [WorkflowTypeValue].[EntityId] = [Block].[Id]
                WHERE [Block].[PageId] IS NOT NULL
                    AND ( [BlockType].[Guid] = 'A8BD05C8-6F89-4628-845B-059E686F089A' OR [BlockType].[Guid] = '9116AAD8-CF16-4BCE-B0CF-5B4D565710ED' )" )
                .ToList();

            var workflowTypeIdByGuid = WorkflowTypeCache.All()
                .Select( w => new
                {
                    w.Id,
                    w.Guid
                } )
                .ToList()
                .ToDictionary( w => w.Guid, w => w.Id );

            var blockIds = workflowEntryBlocks
                .Select( b => b.BlockId )
                .Distinct()
                .ToList();

            var publicBlockIds = new HashSet<int>(
                new BlockService( rockContext ).Queryable()
                    .Include( b => b.Page )
                    .Where( b => blockIds.Contains( b.Id ) )
                    .ToList()
                    .Where( IsWorkflowEntryBlockPublic )
                    .Select( b => b.Id ) );

            var publicWorkflowEntryBlocks = workflowEntryBlocks
                .Where( b => publicBlockIds.Contains( b.BlockId ) )
                .ToList();

            if ( publicWorkflowEntryBlocks.Any( b => b.WorkflowTypeGuid.IsNullOrWhiteSpace() ) )
            {
                return new HashSet<int>( workflowTypeIdByGuid.Values );
            }

            return new HashSet<int>(
                publicWorkflowEntryBlocks
                    .Select( b => b.WorkflowTypeGuid.AsGuidOrNull() )
                    .Where( g => g.HasValue && workflowTypeIdByGuid.ContainsKey( g.Value ) )
                    .Select( g => workflowTypeIdByGuid[g.Value] ) );
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

        private bool? IsWorkflowActionTypePublic( RockContext rockContext, int workflowActionTypeId, ISet<int> publicWorkflowEntryWorkflowTypeIds )
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

            if ( workflowType == null )
            {
                return null;
            }

            var hasPublicWorkflowEntryBlock = publicWorkflowEntryWorkflowTypeIds == null
                ? GetPublicWorkflowEntryWorkflowTypeIds( rockContext ).Contains( workflowTypeId.Value )
                : publicWorkflowEntryWorkflowTypeIds.Contains( workflowTypeId.Value );

            return AllowsPublicView( workflowType ) && hasPublicWorkflowEntryBlock;
        }

        private bool AllowsPublicView( ISecured secured )
        {
            var tempPerson = new Person();
            tempPerson.Guid = Guid.Empty;
            tempPerson.Id = 0;
            return Authorization.Authorized(secured, Authorization.VIEW, tempPerson);
        }

        public bool IsWorkflowEntryBlockPublic( Block block )
        {
            return block != null &&
                block.Page != null &&
                AllowsPublicView( block ) && AllowsPublicView( block.Page );
        }

        private class AttributeValueEntityContext
        {
            public int? EntityId { get; set; }

            public int? AttributeEntityTypeId { get; set; }
        }

        private class WorkflowEntryBlockContext
        {
            public int BlockId { get; set; }

            public string WorkflowTypeGuid { get; set; }
        }
    }
}
