using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Attribute;
using Rock.Blocks;
using Rock.Data;
using Rock.Security;
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
    [EncryptedTextField( "Lava Approval OpenAI API Key",
        "The OpenAI API key to use when an approver requests AI review from this block.",
        false,
        key: AttributeKey.LavaApprovalOpenAIApiKey,
        order: 0,
        isPassword: true )]
    [TextField( "Lava Approval OpenAI Model",
        "The OpenAI model name to use when evaluating Lava approval content. Defaults to gpt-4o-mini if blank.",
        false,
        key: AttributeKey.LavaApprovalOpenAIModel,
        order: 1 )]
    public class LavaApprovalList : RockBlockType
    {
        private class AttributeKey
        {
            public const string LavaApprovalOpenAIApiKey = "LavaApprovalOpenAIApiKey";

            public const string LavaApprovalOpenAIModel = "LavaApprovalOpenAIModel";
        }

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
                IsAIReviewConfigured = GetAttributeValue( AttributeKey.LavaApprovalOpenAIApiKey ).IsNotNullOrWhiteSpace(),
                Sources = GetLavaApprovalSources()
            };
        }

        [BlockAction]
        public BlockActionResult GetSourceContent( string contentHash )
        {
            if ( !CanView() )
            {
                return ActionForbidden( "Not authorized to view Lava approvals." );
            }

            if ( contentHash.IsNullOrWhiteSpace() )
            {
                return ActionBadRequest( "A content hash is required." );
            }

            var currentSources = GetCurrentSourcesByContentHash( contentHash );
            if ( !currentSources.Any() )
            {
                return ActionNotFound( "No current source content was found for this content hash. Run the Security Audit job again before approving it." );
            }

            var firstSource = currentSources.First();
            var content = GetCurrentSourceContent( firstSource );

            return ActionOk( new LavaApprovalContentBag
            {
                Content = content,
                ContentHash = firstSource.ContentHash,
                AIReviewDetails = firstSource.AIReviewDetails,
                AIRiskAssessment = firstSource.AIRiskAssessment,
                AIHasVulnerabilityConcerns = firstSource.AIHasVulnerabilityConcerns,
                AIReviewDateTime = LavaApprovalBag.FromEntity( firstSource, currentSources.Count, false ).AIReviewDateTime,
                Sources = currentSources.Select( s => LavaApprovalBag.FromEntity( s, currentSources.Count, false ) ).ToList()
            } );
        }

        [BlockAction]
        public BlockActionResult Approve( string contentHash, string note )
        {
            if ( !CanEdit() )
            {
                return ActionForbidden( "Not authorized to approve Lava scripts." );
            }

            if ( contentHash.IsNullOrWhiteSpace() )
            {
                return ActionBadRequest( "A content hash is required." );
            }

            var currentSources = GetCurrentSourcesByContentHash( contentHash );
            if ( !currentSources.Any() )
            {
                return ActionNotFound( "No current source content was found for this content hash. Run the Security Audit job again before approving it." );
            }

            var firstSource = currentSources.First();
            var content = GetCurrentSourceContent( firstSource );

            var approvalService = new LavaApprovalService( RockContext );
            var existingApproval = approvalService.Queryable()
                .FirstOrDefault( a => a.ContentHash == firstSource.ContentHash );

            if ( existingApproval == null )
            {
                approvalService.Add( new LavaApproval
                {
                    ContentHash = firstSource.ContentHash,
                    ApprovedDateTime = RockDateTime.Now,
                    ApprovedByPersonAliasId = RequestContext.CurrentPerson?.PrimaryAliasId,
                    ApprovalNote = note,
                    ApprovedContent = content
                } );
                RockContext.SaveChanges();
            }

            return ActionOk();
        }

        [BlockAction]
        public BlockActionResult ReviewWithAI( List<string> contentHashes )
        {
            if ( !CanEdit() )
            {
                return ActionForbidden( "Not authorized to review Lava scripts with AI." );
            }

            if ( contentHashes == null || !contentHashes.Any( h => h.IsNotNullOrWhiteSpace() ) )
            {
                return ActionBadRequest( "At least one content hash is required." );
            }

            var openAIApiKey = GetAttributeValue( AttributeKey.LavaApprovalOpenAIApiKey );
            if ( openAIApiKey.IsNullOrWhiteSpace() )
            {
                return ActionBadRequest( "An OpenAI API key must be configured on the block before AI review can be used." );
            }
            openAIApiKey = Encryption.DecryptString(openAIApiKey);

            var summary = new LavaApprovalAiEvaluator().EvaluateApprovalRequiredContent(
                RockContext,
                openAIApiKey,
                GetAttributeValue( AttributeKey.LavaApprovalOpenAIModel ),
                contentHashes );

            if ( summary.HasError )
            {
                return ActionBadRequest( summary.ErrorMessage );
            }

            return ActionOk( summary );
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

            return sources
                .Where( s => !approvalHashSet.Contains( s.ContentHash ) )
                .GroupBy( s => s.ContentHash, StringComparer.OrdinalIgnoreCase )
                .OrderByDescending( g => g.Max( s => s.DetectedDateTime ) )
                .ThenBy( g => g.Key )
                .Select( g => LavaApprovalBag.FromContentHash( g.Key, g.ToList(), false ) )
                .ToList();
        }

        private List<LavaApprovalSource> GetCurrentSourcesByContentHash( string contentHash )
        {
            if ( contentHash.IsNullOrWhiteSpace() )
            {
                return new List<LavaApprovalSource>();
            }

            return new LavaApprovalSourceService( RockContext ).Queryable()
                .Where( s => s.HasApprovalRequiredLava && s.ContentHash == contentHash )
                .ToList()
                .Where( s => string.Equals( ComputeContentHash( GetCurrentSourceContent( s ) ), contentHash, StringComparison.OrdinalIgnoreCase ) )
                .OrderBy( s => s.TableName )
                .ThenBy( s => s.ColumnName )
                .ThenBy( s => s.RowId )
                .ToList();
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
                new LavaSourceTarget( "HtmlContent", "Content" ),
                new LavaSourceTarget( "Block", "PreHtml" ),
                new LavaSourceTarget( "Block", "PostHtml" ),
                new LavaSourceTarget( "LavaShortcode", "Markup" ),
                new LavaSourceTarget( "ContentChannelItem", "Content" )
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
