using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Blocks;
using Rock.Data;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "Lava Approval List" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Lists Lava scripts that require administrator approval." )]
    [SupportedSiteTypes( Rock.Model.SiteType.Web )]
    [Rock.SystemGuid.EntityTypeGuid( "81c3194f-db46-4a7e-aaff-4dfdcc66d5f4" )]
    [Rock.SystemGuid.BlockTypeGuid( "f15a9d07-140a-4180-bb75-dd640c73db04" )]
    public class LavaApprovalList : RockBlockType
    {
        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/lavaApprovalList.obs";

        public override object GetObsidianBlockInitialization()
        {
            if ( !CanView() )
            {
                return new LavaApprovalsInitializationBox { ErrorMessage = "Not authorized to view Lava approvals." };
            }

            return new LavaApprovalsInitializationBox
            {
                IsEditable = CanEdit(),
                Sources = GetLavaApprovalSources()
            };
        }

        [BlockAction]
        public BlockActionResult GetSourceContent( string idKey )
        {
            if ( !CanView() )
            {
                return ActionForbidden( "Not authorized to view Lava approvals." );
            }

            var source = GetSource( idKey );
            if ( source == null )
            {
                return ActionNotFound( "Lava approval source was not found." );
            }

            if ( !source.HasApprovalRequiredLava || source.ContentHash.IsNullOrWhiteSpace() )
            {
                return ActionBadRequest( "The selected source does not contain approval-required Lava." );
            }

            var content = GetCurrentSourceContent( source );
            if ( content == null )
            {
                return ActionNotFound( "The source content was not found." );
            }

            var contentHash = ComputeContentHash( content );
            if ( !string.Equals( contentHash, source.ContentHash, StringComparison.OrdinalIgnoreCase ) )
            {
                return ActionBadRequest( "The source content has changed since it was scanned. Run the Security Audit job again before approving it." );
            }

            return ActionOk( new LavaApprovalContentBag
            {
                Content = content,
                ContentHash = contentHash
            } );
        }

        [BlockAction]
        public BlockActionResult Approve( string idKey, string note )
        {
            if ( !CanEdit() )
            {
                return ActionForbidden( "Not authorized to approve Lava scripts." );
            }

            var source = GetSource( idKey );
            if ( source == null )
            {
                return ActionNotFound( "Lava approval source was not found." );
            }

            if ( !source.HasApprovalRequiredLava || source.ContentHash.IsNullOrWhiteSpace() )
            {
                return ActionBadRequest( "The selected source does not contain approval-required Lava." );
            }

            var content = GetCurrentSourceContent( source );
            if ( content == null )
            {
                return ActionNotFound( "The source content was not found." );
            }

            var contentHash = ComputeContentHash( content );
            if ( !string.Equals( contentHash, source.ContentHash, StringComparison.OrdinalIgnoreCase ) )
            {
                return ActionBadRequest( "The source content has changed since it was scanned. Run the Security Audit job again before approving it." );
            }

            var approvalService = new LavaApprovalService( RockContext );
            var existingApproval = approvalService.Queryable()
                .FirstOrDefault( a => a.ContentHash == source.ContentHash );

            if ( existingApproval == null )
            {
                approvalService.Add( new LavaApproval
                {
                    ContentHash = source.ContentHash,
                    ApprovedDateTime = RockDateTime.Now,
                    ApprovedByPersonAliasId = RequestContext.CurrentPerson?.PrimaryAliasId,
                    ApprovalNote = note,
                    ApprovedContent = content
                } );
                RockContext.SaveChanges();
            }

            return ActionOk();
        }

        private System.Collections.Generic.List<LavaApprovalBag> GetLavaApprovalSources()
        {
            var approvals = new LavaApprovalService( RockContext ).Queryable()
                .Select( a => a.ContentHash )
                .ToList();

            var approvalHashSet = new System.Collections.Generic.HashSet<string>( approvals, StringComparer.OrdinalIgnoreCase );

            var sources = new LavaApprovalSourceService( RockContext ).Queryable()
                .Where( s => s.HasApprovalRequiredLava && s.ContentHash != null )
                .ToList();

            var sourceCountsByHash = sources
                .GroupBy( s => s.ContentHash, StringComparer.OrdinalIgnoreCase )
                .ToDictionary( g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase );

            return sources
                .Where( s => !approvalHashSet.Contains( s.ContentHash ) )
                .OrderByDescending( s => s.DetectedDateTime )
                .ThenBy( s => s.TableName )
                .ThenBy( s => s.RowId )
                .Select( s => LavaApprovalBag.FromEntity( s, sourceCountsByHash.ContainsKey( s.ContentHash ) ? sourceCountsByHash[s.ContentHash] : 1, false ) )
                .ToList();
        }

        private LavaApprovalSource GetSource( string idKey )
        {
            if ( idKey.IsNullOrWhiteSpace() )
            {
                return null;
            }

            return new LavaApprovalSourceService( RockContext ).Get( idKey, !PageCache.Layout.Site.DisablePredictableIds );
        }

        private string GetCurrentSourceContent( LavaApprovalSource source )
        {
            var target = GetAllowedSourceTarget( source.TableName, source.ColumnName );
            if ( target == null )
            {
                return null;
            }

            return RockContext.Database.SqlQuery<string>(
                string.Format( "SELECT [{0}] FROM [dbo].[{1}] WHERE [Id] = @RowId", target.ColumnName, target.TableName ),
                new SqlParameter( "@RowId", source.RowId ) ).FirstOrDefault();
        }

        private LavaSourceTarget GetAllowedSourceTarget( string tableName, string columnName )
        {
            return GetAllowedSourceTargets()
                .FirstOrDefault( t => t.TableName.Equals( tableName, StringComparison.OrdinalIgnoreCase ) && t.ColumnName.Equals( columnName, StringComparison.OrdinalIgnoreCase ) );
        }

        private List<LavaSourceTarget> GetAllowedSourceTargets()
        {
            return new List<LavaSourceTarget>
            {
                new LavaSourceTarget( "AttributeValue", "Value" ),
                new LavaSourceTarget( "HtmlContent", "Content" )
            };
        }

        private string ComputeContentHash( string content )
        {
            using ( var sha256 = SHA256.Create() )
            {
                var hashBytes = sha256.ComputeHash( Encoding.UTF8.GetBytes( content ?? string.Empty ) );
                return string.Concat( hashBytes.Select( b => b.ToString( "x2" ) ) );
            }
        }

        private bool CanView() => new LavaApprovalSource { Id = 0 }.IsAuthorized( Rock.Security.Authorization.VIEW, RequestContext.CurrentPerson );

        private bool CanEdit() => new LavaApproval { Id = 0 }.IsAuthorized( Rock.Security.Authorization.EDIT, RequestContext.CurrentPerson );

        private class LavaSourceTarget
        {
            public LavaSourceTarget( string tableName, string columnName )
            {
                TableName = tableName;
                ColumnName = columnName;
            }

            public string TableName { get; private set; }

            public string ColumnName { get; private set; }
        }
    }
}
