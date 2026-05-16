using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Data.SqlClient;
using System.Data.Entity;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;

using net.redeemertech.Security.Model;
using Quartz;

using Rock;
using Rock.Attribute;
using Rock.Communication;
using Rock.Data;
using Rock.Jobs;
using Rock.Model;
using Rock.Security;
using Rock.Utility.Enums;
using Rock.Web.Cache;

namespace net.redeemertech.Security
{
    [DisplayName( "Security Audit" )]
    [Description( "Audits Rock security settings, security role membership, binary file type view permissions, document type view permissions, workflow entry block configuration, and workflow type view permissions." )]
    [BinaryFileTypesField( "Binary File Types To Ignore",
        "A whitelist of binary file types that should be open to the public and should not be included in this audit.",
        false,
        key: AttributeKey.BinaryFileTypesToIgnore,
        order: 0 )]
    [DocumentTypeField( "Document Types To Ignore",
        "A whitelist of document types that should be open to the public and should not be included in this audit.",
        false,
        key: AttributeKey.DocumentTypesToIgnore,
        order: 1,
        AllowMultiple = true )]
    [WorkflowTypeField( "Workflow Types To Ignore",
        "A whitelist of workflow types that should be open to the public and should not be included in the Workflow Security audit.",
        allowMultiple: true,
        required: false,
        key: AttributeKey.WorkflowTypesToIgnore,
        order: 2 )]
    [TextField( "Results Email Addresses",
        "A comma-delimited list of email addresses that should receive the formatted security audit results. Leave the standard job notification status set to None to avoid duplicate built-in job notification emails.",
        false,
        key: AttributeKey.ResultsEmailAddresses,
        order: 3 )]
    [EncryptedTextField( "Lava Approval OpenAI API Key",
        "The OpenAI API key to use for evaluating Lava approval content for XSS and SQL injection concerns. Leave blank to skip AI evaluation during this job.",
        false,
        key: AttributeKey.LavaApprovalOpenAIApiKey,
        order: 4,
        isPassword: true )]
    [TextField( "Lava Approval OpenAI Model",
        "The OpenAI model name to use when evaluating Lava approval content. Defaults to gpt-4o-mini if blank.",
        false,
        key: AttributeKey.LavaApprovalOpenAIModel,
        order: 5 )]
    [DisallowConcurrentExecution]
    public class SecurityAudit : RockJob
    {
        private const string SecurityPluginVersionsUrl = "https://security.redeemertech.com/security-plugin-versions.json";
        private const string SecurityRoleMembershipSnapshotSystemSettingKey = "net.redeemertech.SecurityAudit.SecurityRoleMembershipSnapshot";
        private const string SecurityRoleMembershipSnapshotSystemSettingGuid = "08e7a104-f535-4403-a73e-240cdf8daf49";
        private const int LavaApprovalScanBatchSize = 10000;

        private static string SecurityPluginVersion
        {
            get
            {
                return FileVersionInfo.GetVersionInfo( typeof( SecurityAudit ).Assembly.Location ).FileVersion;
            }
        }

        private class AttributeKey
        {
            public const string BinaryFileTypesToIgnore = "BinaryFileTypesToIgnore";

            public const string DocumentTypesToIgnore = "DocumentTypesToIgnore";

            public const string WorkflowTypesToIgnore = "WorkflowTypesToIgnore";

            public const string ResultsEmailAddresses = "ResultsEmailAddresses";

            public const string LavaApprovalOpenAIApiKey = "LavaApprovalOpenAIApiKey";

            public const string LavaApprovalOpenAIModel = "LavaApprovalOpenAIModel";
        }

        public override void Execute()
        {
            using ( var rockContext = new RockContext() )
            {
                var checkResults = new List<AuditCheckResult>
                {
                    AuditSecurityPluginVersion(),
                    AuditDisablePredictableIds(),
                    AuditAccountProtectionProfileSettings( rockContext ),
                    AuditPasswordRegularExpression(),
                    AuditSecurityRoleMemberships( rockContext ),
                    AuditSqlInjectionContent( rockContext ),
                    AuditUnapprovedLavaScripts( rockContext ),
                    AuditBinaryFileTypeSecurity( rockContext ),
                    AuditDocumentTypeSecurity( rockContext ),
                    AuditWorkflowSecurity( rockContext ),
                    AuditAddPersonToGroupWorkflowSecurity( rockContext )
                };

                var lavaApprovalOpenAIApiKey = GetAttributeValue( AttributeKey.LavaApprovalOpenAIApiKey );
                if ( lavaApprovalOpenAIApiKey.IsNotNullOrWhiteSpace() )
                {
                    lavaApprovalOpenAIApiKey = Encryption.DecryptString(lavaApprovalOpenAIApiKey);
                    EvaluateLavaApprovalsWithAI( rockContext, lavaApprovalOpenAIApiKey, GetAttributeValue( AttributeKey.LavaApprovalOpenAIModel ) );
                }

                AddLavaApprovalRiskSummary( rockContext, checkResults.FirstOrDefault( c => c.Name == "Lava Approvals" ) );

                var passingCheckCount = checkResults.Count( c => c.IsPassing );
                var jobResult = new StringBuilder();
                jobResult.AppendFormat( "{0} of {1} security audit checks passed.", passingCheckCount, checkResults.Count );

                foreach ( var checkResult in checkResults )
                {
                    //jobResult.AppendLine();
                    //jobResult.AppendLine();
                    jobResult.AppendLine( checkResult.Summary );

                    //if ( checkResult.Details.IsNotNullOrWhiteSpace() )
                    //{
                    //    jobResult.AppendLine( checkResult.Details );
                    //}

                    //if ( checkResult.SecurityNotices != null && checkResult.SecurityNotices.Any() )
                    //{
                    //    jobResult.AppendLine( "Security Notices:" );
                    //    foreach ( var notice in checkResult.SecurityNotices )
                    //    {
                    //        jobResult.AppendLine( notice );
                    //    }
                    //}
                }

                this.Result = jobResult.ToString();

                var resultsEmailAddresses = GetAttributeValue( AttributeKey.ResultsEmailAddresses );
                if ( resultsEmailAddresses.IsNotNullOrWhiteSpace() )
                {
                    SendResultsEmail( resultsEmailAddresses, checkResults, passingCheckCount );
                }
            }
        }

        private void EvaluateLavaApprovalsWithAI( RockContext rockContext, string openAIApiKey, string aiModel )
        {
            try
            {
                var approvedContentHashes = new LavaApprovalService( rockContext ).Queryable()
                    .AsNoTracking()
                    .Select( a => a.ContentHash )
                    .ToList();

                var approvedContentHashSet = new HashSet<string>( approvedContentHashes, StringComparer.OrdinalIgnoreCase );
                var reviewedContentHashes = new LavaApprovalSourceService( rockContext ).Queryable()
                    .AsNoTracking()
                    .Where( s => s.HasApprovalRequiredLava && s.ContentHash != null && s.AIReviewDateTime.HasValue )
                    .Select( s => s.ContentHash )
                    .Distinct()
                    .ToList();

                var reviewedContentHashSet = new HashSet<string>( reviewedContentHashes, StringComparer.OrdinalIgnoreCase );
                var unreviewedContentHashes = new LavaApprovalSourceService( rockContext ).Queryable()
                    .AsNoTracking()
                    .Where( s => s.HasApprovalRequiredLava && s.ContentHash != null )
                    .Select( s => s.ContentHash )
                    .ToList()
                    .Where( h => !approvedContentHashSet.Contains( h ) && !reviewedContentHashSet.Contains( h ) )
                    .Distinct( StringComparer.OrdinalIgnoreCase )
                    .ToList();

                if ( unreviewedContentHashes.Any() )
                {
                    UpdateLastStatusMessage( string.Format( "AI Lava Evaluations 0/{0}", unreviewedContentHashes.Count ) );
                    new LavaApprovalAiEvaluator().EvaluateApprovalRequiredContent(
                        rockContext,
                        openAIApiKey,
                        aiModel,
                        unreviewedContentHashes,
                        ( completed, total ) => UpdateLastStatusMessage( string.Format( "AI Lava Evaluations {0}/{1}", completed, total ) ) );
                }
            }
            catch
            {
                // AI review failures should not affect the audit email result.
            }
        }

        private void AddLavaApprovalRiskSummary( RockContext rockContext, AuditCheckResult lavaApprovalResult )
        {
            if ( lavaApprovalResult == null || lavaApprovalResult.LavaApprovalFindings == null || !lavaApprovalResult.LavaApprovalFindings.Any() )
            {
                return;
            }

            var outstandingHashSet = new HashSet<string>(
                lavaApprovalResult.LavaApprovalFindings
                    .Select( f => f.ContentHash )
                    .Where( h => h.IsNotNullOrWhiteSpace() ),
                StringComparer.OrdinalIgnoreCase );

            var riskFindings = new LavaApprovalSourceService( rockContext ).Queryable()
                .AsNoTracking()
                .Where( s => s.HasApprovalRequiredLava && s.ContentHash != null && ( s.AIRiskAssessment == "high" || s.AIRiskAssessment == "medium" ) )
                .Select( s => new
                {
                    s.ContentHash,
                    s.AIRiskAssessment,
                    s.IsPublic
                } )
                .ToList()
                .Where( s => outstandingHashSet.Contains( s.ContentHash ) )
                .ToList();

            var highRiskContentHashes = riskFindings
                .Where( s => s.AIRiskAssessment == "high" )
                .Select( s => s.ContentHash )
                .Distinct( StringComparer.OrdinalIgnoreCase )
                .OrderBy( h => h )
                .ToList();

            var publicHighOrMediumRiskContentHashes = riskFindings
                .Where( s => s.IsPublic == true )
                .Select( s => s.ContentHash )
                .Distinct( StringComparer.OrdinalIgnoreCase )
                .OrderBy( h => h )
                .ToList();

            var failingContentHashSet = new HashSet<string>( highRiskContentHashes, StringComparer.OrdinalIgnoreCase );
            failingContentHashSet.UnionWith(
                riskFindings
                    .Where( s => s.IsPublic == true && s.AIRiskAssessment == "medium" )
                    .Select( s => s.ContentHash ) );

            lavaApprovalResult.IsPassing = !failingContentHashSet.Any();
            lavaApprovalResult.Summary = string.Format(
                "Lava Approvals: AI flagged {0} unapproved high risk content hash(es). {1} unapproved public high or medium risk content hash(es) are waiting for approval.",
                highRiskContentHashes.Count,
                publicHighOrMediumRiskContentHashes.Count );
        }

        private AuditCheckResult AuditBinaryFileTypeSecurity( RockContext rockContext )
        {
            var ignoredBinaryFileTypeGuids =
                ( GetAttributeValue( AttributeKey.BinaryFileTypesToIgnore ) ?? string.Empty )
                    .SplitDelimitedValues()
                    .AsGuidList();

            var fileCountsByFileTypeId = new BinaryFileService( rockContext ).Queryable()
                .Where( f => f.BinaryFileTypeId.HasValue )
                .GroupBy( f => f.BinaryFileTypeId.Value )
                .Select( f => new
                {
                    BinaryFileTypeId = f.Key,
                    FileCount = f.Count()
                } )
                .ToDictionary( f => f.BinaryFileTypeId, f => f.FileCount );

            var fileTypeAuditResults = new BinaryFileTypeService( rockContext ).Queryable()
                .Where( f => !ignoredBinaryFileTypeGuids.Contains( f.Guid ) )
                .OrderBy( f => f.Name )
                .ToList()
                .Select( f => new FileTypeAuditResult
                {
                    Id = f.Id,
                    Guid = f.Guid.ToString(),
                    Name = f.Name,
                    RequiresViewSecurity = f.RequiresViewSecurity,
                    AllowsPublicView = f.IsAuthorized( Authorization.VIEW, null ),
                    AllowsAllAuthenticatedUsersView = Authorization.Authorized( f, Authorization.VIEW, SpecialRole.AllAuthenticatedUsers ),
                    FileCount = fileCountsByFileTypeId.ContainsKey( f.Id ) ? fileCountsByFileTypeId[f.Id] : 0
                } )
                .ToList();

            var insecureFileTypes = fileTypeAuditResults
                .Where( f => !f.IsSecure )
                .ToList();

            var secureFileTypeCount = fileTypeAuditResults.Count - insecureFileTypes.Count;
            var details = new StringBuilder();

            foreach ( var fileType in insecureFileTypes )
            {
                details.AppendLine();
                details.AppendFormat(
                    "{0} (Id: {1}, Guid: {2}) is not secure. Binary files: {3}. Reasons: {4}.",
                    fileType.Name,
                    fileType.Id,
                    fileType.Guid,
                    fileType.FileCount,
                    string.Join( "; ", fileType.Reasons ) );
            }

            return new AuditCheckResult
            {
                Name = "Binary File Type Security",
                IsPassing = !insecureFileTypes.Any(),
                Summary = string.Format(
                    "Binary File Type Security: {0} of {1} checked binary file types are secure. {2} binary file types are not secure. {3} binary file types were ignored.",
                    secureFileTypeCount,
                    fileTypeAuditResults.Count,
                    insecureFileTypes.Count,
                    ignoredBinaryFileTypeGuids.Count ),
                Details = details.ToString(),
                InsecureFileTypes = insecureFileTypes
            };
        }

        private AuditCheckResult AuditDocumentTypeSecurity( RockContext rockContext )
        {
            var ignoredDocumentTypeGuids =
                ( GetAttributeValue( AttributeKey.DocumentTypesToIgnore ) ?? string.Empty )
                    .SplitDelimitedValues()
                    .AsGuidList();

            var documentCountsByDocumentTypeId = new DocumentService( rockContext ).Queryable()
                .GroupBy( d => d.DocumentTypeId )
                .Select( d => new
                {
                    DocumentTypeId = d.Key,
                    DocumentCount = d.Count()
                } )
                .ToDictionary( d => d.DocumentTypeId, d => d.DocumentCount );

            var documentTypeAuditResults = new DocumentTypeService( rockContext ).Queryable()
                .Where( d => !ignoredDocumentTypeGuids.Contains( d.Guid ) )
                .OrderBy( d => d.Name )
                .ToList()
                .Select( d => new DocumentTypeAuditResult
                {
                    Id = d.Id,
                    Guid = d.Guid.ToString(),
                    Name = d.Name,
                    EntityType = d.EntityType != null ? d.EntityType.FriendlyName : string.Empty,
                    AllowsPublicView = d.IsAuthorized( Authorization.VIEW, null ),
                    AllowsAllAuthenticatedUsersView = Authorization.Authorized( d, Authorization.VIEW, SpecialRole.AllAuthenticatedUsers ),
                    DocumentCount = documentCountsByDocumentTypeId.ContainsKey( d.Id ) ? documentCountsByDocumentTypeId[d.Id] : 0
                } )
                .ToList();

            var insecureDocumentTypes = documentTypeAuditResults
                .Where( d => !d.IsSecure )
                .ToList();

            var secureDocumentTypeCount = documentTypeAuditResults.Count - insecureDocumentTypes.Count;
            var details = new StringBuilder();

            foreach ( var documentType in insecureDocumentTypes )
            {
                details.AppendLine();
                details.AppendFormat(
                    "{0} (Id: {1}, Guid: {2}) is not secure. Documents: {3}. Reasons: {4}.",
                    documentType.Name,
                    documentType.Id,
                    documentType.Guid,
                    documentType.DocumentCount,
                    string.Join( "; ", documentType.Reasons ) );
            }

            return new AuditCheckResult
            {
                Name = "Document Type Security",
                IsPassing = !insecureDocumentTypes.Any(),
                Summary = string.Format(
                    "Document Type Security: {0} of {1} checked document types are secure. {2} document types are not secure. {3} document types were ignored.",
                    secureDocumentTypeCount,
                    documentTypeAuditResults.Count,
                    insecureDocumentTypes.Count,
                    ignoredDocumentTypeGuids.Count ),
                Details = details.ToString(),
                InsecureDocumentTypes = insecureDocumentTypes
            };
        }

        private AuditCheckResult AuditWorkflowSecurity( RockContext rockContext )
        {
            var publicEvaluator = new LavaApprovalSourcePublicEvaluator();
            var ignoredWorkflowTypeGuids =
                ( GetAttributeValue( AttributeKey.WorkflowTypesToIgnore ) ?? string.Empty )
                    .SplitDelimitedValues()
                    .AsGuidList();

            var workflowEntryBlockIdsWithNoWorkflowType = rockContext.Database.SqlQuery<int>( @"
                DECLARE @BlockEntityTypeId INT = (SELECT [Id] FROM [EntityType] WHERE [Name] = 'Rock.Model.Block')

                SELECT DISTINCT [Block].[Id]
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
                AND ( [BlockType].[Guid] = 'A8BD05C8-6F89-4628-845B-059E686F089A' OR [BlockType].[Guid] = '9116AAD8-CF16-4BCE-B0CF-5B4D565710ED' )
                AND (
                    [WorkflowTypeAttribute].[Id] IS NULL
                    OR COALESCE(NULLIF([WorkflowTypeValue].[Value], ''), NULLIF([WorkflowTypeAttribute].[DefaultValue], '')) IS NULL
                )" )
                .ToList();

            var exposedWorkflowEntryBlocks = new BlockService( rockContext ).Queryable()
                .Include( b => b.BlockType )
                .Include( b => b.Page )
                .Where( b => workflowEntryBlockIdsWithNoWorkflowType.Contains( b.Id ) )
                .ToList()
                .Where( publicEvaluator.IsWorkflowEntryBlockPublic )
                .OrderBy( b => b.Page.InternalName )
                .ThenBy( b => b.Name )
                .Select( b => new WorkflowEntryBlockAuditResult
                {
                    Id = b.Id,
                    Guid = b.Guid.ToString(),
                    Name = b.Name,
                    BlockType = b.BlockType != null ? b.BlockType.Name : string.Empty,
                    PageId = b.Page.Id,
                    PageGuid = b.Page.Guid.ToString(),
                    PageName = b.Page.InternalName
                } )
                .ToList();

            var workflowTypeAuditResults = new WorkflowTypeService( rockContext ).Queryable()
                .Where( w => !ignoredWorkflowTypeGuids.Contains( w.Guid ) )
                .OrderBy( w => w.Name )
                .ToList()
                .Select( w => new WorkflowTypeAuditResult
                {
                    Id = w.Id,
                    Guid = w.Guid.ToString(),
                    Name = w.Name,
                    AllowsAllUsersView = Authorization.Authorized( w, Authorization.VIEW, SpecialRole.AllUsers ),
                    AllowsAllAuthenticatedUsersView = Authorization.Authorized( w, Authorization.VIEW, SpecialRole.AllAuthenticatedUsers )
                } )
                .ToList();

            var insecureWorkflowTypes = workflowTypeAuditResults
                .Where( w => !w.IsSecure )
                .ToList();

            var secureWorkflowTypeCount = workflowTypeAuditResults.Count - insecureWorkflowTypes.Count;
            var details = new StringBuilder();

            foreach ( var block in exposedWorkflowEntryBlocks )
            {
                details.AppendLine();
                details.AppendFormat(
                    "{0} (Id: {1}, Guid: {2}) on page {3} (Id: {4}, Guid: {5}) is viewable by All Users or All Authenticated Users and does not have Workflow Type set.",
                    block.Name,
                    block.Id,
                    block.Guid,
                    block.PageName,
                    block.PageId,
                    block.PageGuid );
            }

            foreach ( var workflowType in insecureWorkflowTypes )
            {
                details.AppendLine();
                details.AppendFormat(
                    "{0} (Id: {1}, Guid: {2}) is not secure. Reasons: {3}.",
                    workflowType.Name,
                    workflowType.Id,
                    workflowType.Guid,
                    string.Join( "; ", workflowType.Reasons ) );
            }

            return new AuditCheckResult
            {
                Name = "Workflow Security",
                IsPassing = !exposedWorkflowEntryBlocks.Any() && !insecureWorkflowTypes.Any(),
                Summary = string.Format(
                    "Workflow Security: {0} exposed workflow entry blocks do not have Workflow Type set. {1} of {2} checked workflow types are secure. {3} workflow types allow All Users or All Authenticated Users to view the workflow type. {4} workflow types were ignored.",
                    exposedWorkflowEntryBlocks.Count,
                    secureWorkflowTypeCount,
                    workflowTypeAuditResults.Count,
                    insecureWorkflowTypes.Count,
                    ignoredWorkflowTypeGuids.Count ),
                Details = details.ToString(),
                InsecureWorkflowEntryBlocks = exposedWorkflowEntryBlocks,
                InsecureWorkflowTypes = insecureWorkflowTypes
            };
        }

        private AuditCheckResult AuditAddPersonToGroupWorkflowSecurity( RockContext rockContext )
        {
            var workflowTypeIds = rockContext.Database.SqlQuery<int>( @"
                WITH Attributes AS (
                    SELECT
                        [Id],
                        [Name],
                        [Key]
                    FROM [Attribute]
                    WHERE EntityTypeId = (SELECT [Id] FROM [EntityType] WHERE [Name] = 'Rock.Model.WorkflowActionType')
                    AND EntityTypeQualifierColumn = 'EntityTypeId'
                    AND EntityTypeQualifierValue = (SELECT CONVERT(VARCHAR(10), [Id]) FROM [EntityType] WHERE [Name] = 'Rock.Workflow.Action.AddPersonToGroupWFAttribute')
                )
                SELECT DISTINCT
                    [WorkflowType].[Id] [WorkflowTypeId]
                FROM WorkflowActionType
                INNER JOIN WorkflowActivityType ON WorkflowActivityType.Id = WorkflowActionType.ActivityTypeId
                INNER JOIN WorkflowType ON WorkflowType.Id = WorkflowActivityType.WorkflowTypeId
                LEFT JOIN [Attributes] [DisableSecurityGroupsAtt] ON [DisableSecurityGroupsAtt].[Key] = 'DisableSecurityGroups'
                LEFT JOIN [Attributes] [LimitToGroupsOfTypeAtt] ON [LimitToGroupsOfTypeAtt].[Key] = 'LimitToGroupsOfType'
                LEFT JOIN [Attributes] [LimitToGroupsUnderSpecificParentGroupAtt] ON [LimitToGroupsUnderSpecificParentGroupAtt].[Key] = 'LimitToGroupsUnderSpecificParentGroup'
                LEFT JOIN [AttributeValue] [DisableSecurityGroupsVal] ON [DisableSecurityGroupsVal].AttributeId = [DisableSecurityGroupsAtt].Id AND [DisableSecurityGroupsVal].EntityId = WorkflowActionType.Id
                LEFT JOIN [AttributeValue] [LimitToGroupsOfTypeVal] ON [LimitToGroupsOfTypeVal].AttributeId = [LimitToGroupsOfTypeAtt].Id AND [LimitToGroupsOfTypeVal].EntityId = WorkflowActionType.Id
                LEFT JOIN [AttributeValue] [LimitToGroupsUnderSpecificParentGroupVal] ON [LimitToGroupsUnderSpecificParentGroupVal].AttributeId = [LimitToGroupsUnderSpecificParentGroupAtt].Id AND [LimitToGroupsUnderSpecificParentGroupVal].EntityId = WorkflowActionType.Id
                WHERE WorkflowActionType.EntityTypeId = (SELECT [Id] FROM [EntityType] WHERE [Name] = 'Rock.Workflow.Action.AddPersonToGroupWFAttribute')
                AND (
                    DisableSecurityGroupsVal.[Value] IS NULL
                    OR
                    DisableSecurityGroupsVal.[Value] = 'False'
                )
                AND TRY_CONVERT(uniqueidentifier, LimitToGroupsOfTypeVal.[Value]) IS NULL
                AND TRY_CONVERT(uniqueidentifier, [LimitToGroupsUnderSpecificParentGroupVal].[Value]) IS NULL
                ORDER BY WorkflowType.Id ASC" )
                .ToList();

            var workflowTypeAuditResults = new WorkflowTypeService( rockContext ).Queryable()
                .Where( w => workflowTypeIds.Contains( w.Id ) )
                .OrderBy( w => w.Name )
                .ToList()
                .Select( w => new WorkflowTypeAuditResult
                {
                    Id = w.Id,
                    Guid = w.Guid.ToString(),
                    Name = w.Name,
                    AllowsAllUsersView = Authorization.Authorized( w, Authorization.VIEW, SpecialRole.AllUsers ),
                    AllowsAllAuthenticatedUsersView = Authorization.Authorized( w, Authorization.VIEW, SpecialRole.AllAuthenticatedUsers )
                } )
                .ToList();

            var insecureWorkflowTypes = workflowTypeAuditResults
                .Where( w => !w.IsSecure )
                .ToList();

            var secureWorkflowTypeCount = workflowTypeAuditResults.Count - insecureWorkflowTypes.Count;
            var details = new StringBuilder();

            foreach ( var workflowType in insecureWorkflowTypes )
            {
                details.AppendLine();
                details.AppendFormat(
                    "{0} (Id: {1}, Guid: {2}) is not secure. Reasons: {3}.",
                    workflowType.Name,
                    workflowType.Id,
                    workflowType.Guid,
                    string.Join( "; ", workflowType.Reasons ) );
            }

            return new AuditCheckResult
            {
                Name = "Add Person To Group Workflow Security",
                IsPassing = !insecureWorkflowTypes.Any(),
                Summary = string.Format(
                    "Add Person To Group Workflow Security: {0} of {1} checked workflow types are secure. {2} workflow types allow All Users or All Authenticated Users to run the workflow.",
                    secureWorkflowTypeCount,
                    workflowTypeAuditResults.Count,
                    insecureWorkflowTypes.Count ),
                Details = details.ToString(),
                InsecureWorkflowTypes = insecureWorkflowTypes
            };
        }

        private AuditCheckResult AuditSqlInjectionContent( RockContext rockContext )
        {
            var findings = new List<SqlInjectionContentFinding>();

            findings.AddRange(
                rockContext.Database.SqlQuery<int>( @"
                    SELECT [Id]
                    FROM [Person]
                    WHERE [LastName] LIKE '%<script%'
                    OR [FirstName] LIKE '%<script%'
                    OR [NickName] LIKE '%<script%'
                    OR [LastName] LIKE '%{%'
                    OR [FirstName] LIKE '%{%'
                    OR [NickName] LIKE '%{%'
                    OR [LastName] LIKE '%}%'
                    OR [FirstName] LIKE '%}%'
                    OR [NickName] LIKE '%}%' " )
                    .ToList()
                    .Select( id => new SqlInjectionContentFinding
                    {
                        TableName = "Person",
                        Id = id
                    } ) );

            findings.AddRange(
                rockContext.Database.SqlQuery<int>( @"
                    SELECT [Id]
                    FROM [Location]
                    WHERE [Street1] LIKE '%<script%'
                    OR [Street2] LIKE '%<script%'
                    OR [City] LIKE '%<script%'
                    OR [PostalCode] LIKE '%<script%'" )
                    .ToList()
                    .Select( id => new SqlInjectionContentFinding
                    {
                        TableName = "Location",
                        Id = id
                    } ) );

            var details = new StringBuilder();
            foreach ( var findingGroup in findings.GroupBy( f => f.TableName ).OrderBy( g => g.Key ) )
            {
                details.AppendFormat(
                    "{0} rows containing '<script': {1}.",
                    findingGroup.Key,
                    string.Join( ", ", findingGroup.OrderBy( f => f.Id ).Select( f => f.Id ) ) );
                details.AppendLine();
            }

            return new AuditCheckResult
            {
                Name = "SQL/XSS Injection Content",
                IsPassing = !findings.Any(),
                Summary = findings.Any()
                    ? string.Format( "SQL/XSS Injection Content: {0} Person or Location rows contain injection content.", findings.Count )
                    : "SQL/XSS Injection Content: no Person or Location rows contain injection content.",
                Details = details.ToString(),
                SqlInjectionContentFindings = findings
            };
        }

        private AuditCheckResult AuditUnapprovedLavaScripts( RockContext rockContext )
        {
            var timingDetails = new List<string>();
            var shortcodeTags = GetLavaShortcodeTags( rockContext );

            foreach ( var target in GetLavaApprovalScanTargets() )
            {
                ScanLavaApprovalTarget( rockContext, target, timingDetails, shortcodeTags );
            }

            RefreshLavaApprovalSourcePublicStatuses( rockContext );
            UpdatePublicLavaShortcodeSources( rockContext );

            var approvedContentHashes = new LavaApprovalService( rockContext ).Queryable()
                .AsNoTracking()
                .Select( a => a.ContentHash )
                .ToList();
            var approvedContentHashSet = new HashSet<string>( approvedContentHashes, StringComparer.OrdinalIgnoreCase );

            var unapprovedSources = new LavaApprovalSourceService( rockContext ).Queryable()
                .AsNoTracking()
                .Where( s => s.HasApprovalRequiredLava && s.ContentHash != null )
                .ToList()
                .Where( s => !approvedContentHashSet.Contains( s.ContentHash ) )
                .OrderBy( s => s.TableName )
                .ThenBy( s => s.ColumnName )
                .ThenBy( s => s.RowId )
                .Select( s => new LavaApprovalFinding
                {
                    TableName = s.TableName,
                    ColumnName = s.ColumnName,
                    RowId = s.RowId,
                    ContentHash = s.ContentHash,
                    ContentPreview = s.ContentPreview
                } )
                .ToList();

            var details = new StringBuilder();
            
            //details.AppendLine( "Stopwatch Debugging:" );
            //foreach ( var timingDetail in timingDetails )
            //{
            //    details.AppendLine( timingDetail );
            //}

            //foreach ( var source in unapprovedSources )
            //{
            //    details.AppendLine();
            //    details.AppendFormat(
            //        "{0}.{1} row {2} contains approval-required Lava. Content hash: {3}.",
            //        source.TableName,
            //        source.ColumnName,
            //        source.RowId,
            //        source.ContentHash );
            //    details.AppendLine();
            //}

            var unapprovedContentHashCount = unapprovedSources
                .Select( s => s.ContentHash )
                .Distinct( StringComparer.OrdinalIgnoreCase )
                .Count();

            return new AuditCheckResult
            {
                Name = "Lava Approvals",
                IsPassing = true,
                Summary = unapprovedSources.Any()
                    ? string.Format( "Lava Approvals: {0} unapproved approval-required content hash(es) are waiting for AI risk review.", unapprovedContentHashCount )
                    : "Lava Approvals: no unapproved approval-required Lava was found.",
                Details = details.ToString(),
                LavaApprovalFindings = unapprovedSources
            };
        }

        private void ScanLavaApprovalTarget( RockContext rockContext, LavaApprovalScanTarget target, List<string> timingDetails, List<string> shortcodeTags )
        {
            var targetStopwatch = Stopwatch.StartNew();
            var afterRowId = 0;
            var batchNumber = 0;
            var totalChangedRows = 0;
            var connection = ( SqlConnection ) rockContext.Database.Connection;
            var shouldCloseConnection = connection.State == System.Data.ConnectionState.Closed;

            if ( shouldCloseConnection )
            {
                connection.Open();
            }

            try
            {
                var removeDeletedStopwatch = Stopwatch.StartNew();
                RemoveDeletedLavaApprovalSources( connection, target );
                removeDeletedStopwatch.Stop();
                timingDetails.Add( string.Format( "{0}.{1} remove deleted sources: {2}.", target.TableName, target.ColumnName, FormatElapsed( removeDeletedStopwatch.Elapsed ) ) );

                var maxTargetRowId = GetMaxLavaApprovalTargetRowId( connection, target );
                timingDetails.Add( string.Format( "{0}.{1} max target RowId: {2}.", target.TableName, target.ColumnName, maxTargetRowId ) );

                while ( afterRowId < maxTargetRowId )
                {
                    batchNumber++;
                    var batchTiming = new LavaApprovalScanBatchTiming
                    {
                        BatchNumber = batchNumber
                    };

                    var stageTable = CreateLavaApprovalSourceStageTable();
                    var changedRowsStopwatch = Stopwatch.StartNew();
                    var windowMaxRowId = PopulateLavaApprovalSourceStageTable( connection, target, afterRowId, stageTable, batchTiming, shortcodeTags );
                    changedRowsStopwatch.Stop();
                    batchTiming.ChangedRowsElapsed = changedRowsStopwatch.Elapsed;

                    if ( !windowMaxRowId.HasValue )
                    {
                        timingDetails.Add( string.Format( "{0}.{1} batch {2}: source-window query found no rows after RowId {3} in {4}.", target.TableName, target.ColumnName, batchNumber, afterRowId, FormatElapsed( batchTiming.ChangedRowsElapsed ) ) );
                        break;
                    }

                    totalChangedRows += batchTiming.ChangedRowCount;
                    afterRowId = windowMaxRowId.Value;

                    if ( batchTiming.ChangedRowCount == 0 )
                    {
                        timingDetails.Add( batchTiming.Format( target ) );
                        continue;
                    }

                    using ( var transaction = connection.BeginTransaction() )
                    {
                        try
                        {
                            CreateLavaApprovalSourceStageTable( connection, transaction );
                            BulkCopyLavaApprovalSourceStageTable( connection, transaction, stageTable, batchTiming );
                            ApplyLavaApprovalSourceStageTable( connection, transaction, batchTiming );
                            transaction.Commit();
                        }
                        catch
                        {
                            transaction.Rollback();
                            throw;
                        }
                    }

                    timingDetails.Add( batchTiming.Format( target ) );
                }
            }
            finally
            {
                if ( shouldCloseConnection )
                {
                    connection.Close();
                }
            }

            targetStopwatch.Stop();
            timingDetails.Add( string.Format( "{0}.{1} total scan: {2} across {3} changed row(s) in {4} batch attempt(s).", target.TableName, target.ColumnName, FormatElapsed( targetStopwatch.Elapsed ), totalChangedRows, batchNumber ) );
        }

        private string FormatElapsed( TimeSpan elapsed )
        {
            return string.Format( "{0:N0} ms", elapsed.TotalMilliseconds );
        }

        private DataTable CreateLavaApprovalSourceStageTable()
        {
            var table = new DataTable();
            table.Columns.Add( "TableName", typeof( string ) );
            table.Columns.Add( "ColumnName", typeof( string ) );
            table.Columns.Add( "RowId", typeof( int ) );
            table.Columns.Add( "SourceChecksum", typeof( long ) );
            table.Columns.Add( "ContentHash", typeof( string ) );
            table.Columns.Add( "HasApprovalRequiredLava", typeof( bool ) );
            table.Columns.Add( "ReferencedShortcodes", typeof( string ) );
            table.Columns.Add( "ContentPreview", typeof( string ) );
            table.Columns.Add( "ScannedDateTime", typeof( DateTime ) );

            return table;
        }

        private int GetMaxLavaApprovalTargetRowId( SqlConnection connection, LavaApprovalScanTarget target )
        {
            using ( var command = connection.CreateCommand() )
            {
                command.CommandText = target.GetMaxRowIdSql();
                var result = command.ExecuteScalar();
                return result == DBNull.Value || result == null ? 0 : Convert.ToInt32( result );
            }
        }

        private int? PopulateLavaApprovalSourceStageTable( SqlConnection connection, LavaApprovalScanTarget target, int afterRowId, DataTable stageTable, LavaApprovalScanBatchTiming batchTiming, List<string> shortcodeTags )
        {
            int? windowMaxRowId = null;
            var scannedDateTime = RockDateTime.Now;
            var publicEvaluator = new LavaApprovalSourcePublicEvaluator();

            using ( var command = connection.CreateCommand() )
            {
                command.CommandText = target.GetChangedRowsSql( LavaApprovalScanBatchSize );
                command.Parameters.Add( new SqlParameter( "@AfterRowId", afterRowId ) );
                command.CommandTimeout = 180;

                using ( var reader = command.ExecuteReader( CommandBehavior.SequentialAccess ) )
                {
                    while ( reader.Read() )
                    {
                        var rowId = reader.GetInt32( 0 );
                        var sourceChecksum = reader.IsDBNull( 1 ) ? ( long? ) null : reader.GetInt64( 1 );
                        var content = reader.IsDBNull( 2 ) ? null : reader.GetString( 2 );

                        batchTiming.ChangedRowCount++;

                        var hasApprovalRequiredLava = false;

                        if ( target.ShouldCheckForApprovalRequiredLava )
                        {
                            var containsLavaStopwatch = Stopwatch.StartNew();
                            hasApprovalRequiredLava = ContainsApprovalRequiredLava( content );
                            containsLavaStopwatch.Stop();
                            batchTiming.ContainsLavaElapsed += containsLavaStopwatch.Elapsed;
                        }
                        else
                        {
                            hasApprovalRequiredLava = content != null;
                        }

                        string contentHash = null;
                        string contentPreview = null;
                        string referencedShortcodes = null;
                        if ( hasApprovalRequiredLava )
                        {
                            referencedShortcodes = string.Join( "|", publicEvaluator.GetReferencedShortcodes( content, shortcodeTags ) );
                        }

                        if ( hasApprovalRequiredLava )
                        {
                            batchTiming.ApprovalRequiredLavaCount++;

                            var contentHashStopwatch = Stopwatch.StartNew();
                            contentHash = ComputeContentHash( content );
                            contentHashStopwatch.Stop();
                            batchTiming.ComputeHashElapsed += contentHashStopwatch.Elapsed;

                            var previewStopwatch = Stopwatch.StartNew();
                            contentPreview = BuildLavaContentPreview( content );
                            previewStopwatch.Stop();
                            batchTiming.BuildPreviewElapsed += previewStopwatch.Elapsed;
                        }

                        stageTable.Rows.Add(
                            target.TableName,
                            target.ColumnName,
                            rowId,
                            sourceChecksum.HasValue ? ( object ) sourceChecksum.Value : DBNull.Value,
                            contentHash ?? ( object ) DBNull.Value,
                            hasApprovalRequiredLava,
                            referencedShortcodes != null ? ( object ) referencedShortcodes : DBNull.Value,
                            contentPreview ?? ( object ) DBNull.Value,
                            scannedDateTime );
                    }

                    if ( reader.NextResult() && reader.Read() && !reader.IsDBNull( 0 ) )
                    {
                        windowMaxRowId = reader.GetInt32( 0 );
                    }
                }
            }

            batchTiming.WindowMaxRowId = windowMaxRowId;
            return windowMaxRowId;
        }

        private void CreateLavaApprovalSourceStageTable( SqlConnection connection, SqlTransaction transaction )
        {
            using ( var command = connection.CreateCommand() )
            {
                command.Transaction = transaction;
                command.CommandText = @"
                    CREATE TABLE #LavaApprovalSourceStage (
                        [TableName] [nvarchar](128) NOT NULL,
                        [ColumnName] [nvarchar](128) NOT NULL,
                        [RowId] [int] NOT NULL,
                        [SourceChecksum] [bigint] NULL,
                        [ContentHash] [nvarchar](64) NULL,
                        [HasApprovalRequiredLava] [bit] NOT NULL,
                        [ReferencedShortcodes] [nvarchar](max) NULL,
                        [ContentPreview] [nvarchar](max) NULL,
                        [ScannedDateTime] [datetime] NOT NULL,
                        PRIMARY KEY ([TableName], [ColumnName], [RowId])
                    );";
                command.ExecuteNonQuery();
            }
        }

        private void UpdatePublicLavaShortcodeSources( RockContext rockContext )
        {
            var approvalSourceService = new LavaApprovalSourceService( rockContext );
            var publicReferencedShortcodes = new HashSet<string>( approvalSourceService.Queryable()
                .Where( s => s.HasApprovalRequiredLava && s.IsPublic == true && s.ReferencedShortcodes != null )
                .Select( s => s.ReferencedShortcodes )
                .ToList()
                .SelectMany( s => s.Split( new[] { '|' }, StringSplitOptions.RemoveEmptyEntries ) ),
                StringComparer.OrdinalIgnoreCase );

            var shortcodeSources = approvalSourceService.Queryable()
                .Where( s => s.HasApprovalRequiredLava && s.TableName == "LavaShortcode" && s.ColumnName == "Markup" )
                .ToList();

            if ( !shortcodeSources.Any() )
            {
                return;
            }

            var shortcodeRows = rockContext.Database.SqlQuery<LavaShortcodeScanContext>( @"
                SELECT [Id], [TagName]
                FROM [dbo].[LavaShortcode]" ).ToList();

            foreach ( var shortcodeSource in shortcodeSources )
            {
                var tagName = shortcodeRows.FirstOrDefault( s => s.Id == shortcodeSource.RowId )?.TagName;
                if ( tagName.IsNullOrWhiteSpace() )
                {
                    shortcodeSource.IsPublic = null;
                    continue;
                }

                shortcodeSource.IsPublic = publicReferencedShortcodes.Contains( tagName )
                    ? ( bool? ) true
                    : null;
            }

            rockContext.SaveChanges();
        }

        private void RefreshLavaApprovalSourcePublicStatuses( RockContext rockContext )
        {
            var publicEvaluator = new LavaApprovalSourcePublicEvaluator();
            var publicWorkflowEntryWorkflowTypeIds = publicEvaluator.GetPublicWorkflowEntryWorkflowTypeIds( rockContext );
            var approvalSourceService = new LavaApprovalSourceService( rockContext );
            var approvalSources = approvalSourceService.Queryable().ToList();

            foreach ( var approvalSource in approvalSources )
            {
                approvalSource.IsPublic = approvalSource.HasApprovalRequiredLava
                    ? publicEvaluator.DetermineIsPublic( rockContext, approvalSource.TableName, approvalSource.RowId, publicWorkflowEntryWorkflowTypeIds )
                    : null;
            }

            rockContext.SaveChanges();
        }

        private List<string> GetLavaShortcodeTags( RockContext rockContext )
        {
            return rockContext.Database.SqlQuery<string>( @"
                SELECT [TagName]
                FROM [dbo].[LavaShortcode]
                WHERE [TagName] IS NOT NULL
                    AND [TagName] <> N''" )
                .ToList();
        }

        private void BulkCopyLavaApprovalSourceStageTable( SqlConnection connection, SqlTransaction transaction, DataTable stageTable, LavaApprovalScanBatchTiming batchTiming )
        {
            var bulkCopyStopwatch = Stopwatch.StartNew();

            using ( var bulkCopy = new SqlBulkCopy( connection, SqlBulkCopyOptions.CheckConstraints, transaction ) )
            {
                bulkCopy.DestinationTableName = "#LavaApprovalSourceStage";
                bulkCopy.BatchSize = stageTable.Rows.Count;
                bulkCopy.ColumnMappings.Add( "TableName", "TableName" );
                bulkCopy.ColumnMappings.Add( "ColumnName", "ColumnName" );
                bulkCopy.ColumnMappings.Add( "RowId", "RowId" );
                bulkCopy.ColumnMappings.Add( "SourceChecksum", "SourceChecksum" );
                bulkCopy.ColumnMappings.Add( "ContentHash", "ContentHash" );
                bulkCopy.ColumnMappings.Add( "HasApprovalRequiredLava", "HasApprovalRequiredLava" );
                bulkCopy.ColumnMappings.Add( "ReferencedShortcodes", "ReferencedShortcodes" );
                bulkCopy.ColumnMappings.Add( "ContentPreview", "ContentPreview" );
                bulkCopy.ColumnMappings.Add( "ScannedDateTime", "ScannedDateTime" );
                bulkCopy.WriteToServer( stageTable );
            }

            bulkCopyStopwatch.Stop();
            batchTiming.BulkCopyElapsed = bulkCopyStopwatch.Elapsed;
        }

        private void ApplyLavaApprovalSourceStageTable( SqlConnection connection, SqlTransaction transaction, LavaApprovalScanBatchTiming batchTiming )
        {
            var applyStopwatch = Stopwatch.StartNew();

            using ( var command = connection.CreateCommand() )
            {
                command.Transaction = transaction;
                command.CommandText = @"
                    SET NOCOUNT ON;

                    SELECT COUNT(*)
                    FROM [dbo].[_net_redeemertech_LavaApprovalSource] target
                    INNER JOIN #LavaApprovalSourceStage stage
                        ON stage.[TableName] = target.[TableName]
                        AND stage.[ColumnName] = target.[ColumnName]
                        AND stage.[RowId] = target.[RowId]
                    WHERE stage.[HasApprovalRequiredLava] = 1
                        AND target.[HasApprovalRequiredLava] = 1
                        AND target.[ContentHash] = stage.[ContentHash];

                    UPDATE target
                    SET
                        target.[SourceChecksum] = stage.[SourceChecksum],
                        target.[ContentHash] = stage.[ContentHash],
                        target.[HasApprovalRequiredLava] = stage.[HasApprovalRequiredLava],
                        target.[ReferencedShortcodes] = stage.[ReferencedShortcodes],
                        target.[ContentPreview] = stage.[ContentPreview],
                        target.[LastScannedDateTime] = stage.[ScannedDateTime],
                        target.[ModifiedDateTime] = stage.[ScannedDateTime],
                        target.[DetectedDateTime] = CASE
                            WHEN stage.[HasApprovalRequiredLava] = 1 AND target.[DetectedDateTime] IS NULL THEN stage.[ScannedDateTime]
                            WHEN stage.[HasApprovalRequiredLava] = 0 THEN NULL
                            ELSE target.[DetectedDateTime]
                        END
                    FROM [dbo].[_net_redeemertech_LavaApprovalSource] target
                    INNER JOIN #LavaApprovalSourceStage stage
                        ON stage.[TableName] = target.[TableName]
                        AND stage.[ColumnName] = target.[ColumnName]
                        AND stage.[RowId] = target.[RowId];

                    SELECT @@ROWCOUNT;

                    INSERT INTO [dbo].[_net_redeemertech_LavaApprovalSource] (
                        [TableName],
                        [ColumnName],
                        [RowId],
                        [SourceChecksum],
                        [ContentHash],
                        [HasApprovalRequiredLava],
                        [ReferencedShortcodes],
                        [ContentPreview],
                        [LastScannedDateTime],
                        [DetectedDateTime],
                        [CreatedDateTime],
                        [ModifiedDateTime],
                        [Guid]
                    )
                    SELECT
                        stage.[TableName],
                        stage.[ColumnName],
                        stage.[RowId],
                        stage.[SourceChecksum],
                        stage.[ContentHash],
                        stage.[HasApprovalRequiredLava],
                        stage.[ReferencedShortcodes],
                        stage.[ContentPreview],
                        stage.[ScannedDateTime],
                        CASE WHEN stage.[HasApprovalRequiredLava] = 1 THEN stage.[ScannedDateTime] ELSE NULL END,
                        stage.[ScannedDateTime],
                        stage.[ScannedDateTime],
                        NEWID()
                    FROM #LavaApprovalSourceStage stage
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM [dbo].[_net_redeemertech_LavaApprovalSource] target
                        WHERE target.[TableName] = stage.[TableName]
                            AND target.[ColumnName] = stage.[ColumnName]
                            AND target.[RowId] = stage.[RowId]
                    );

                    SELECT @@ROWCOUNT;

                    DROP TABLE #LavaApprovalSourceStage;";

                using ( var reader = command.ExecuteReader() )
                {
                    if ( reader.Read() )
                    {
                        batchTiming.UnchangedApprovalRequiredLavaCount = reader.GetInt32( 0 );
                    }

                    if ( reader.NextResult() && reader.Read() )
                    {
                        batchTiming.ExistingSourceCount = reader.GetInt32( 0 );
                    }

                    if ( reader.NextResult() && reader.Read() )
                    {
                        batchTiming.NewSourceCount = reader.GetInt32( 0 );
                    }
                }
            }

            applyStopwatch.Stop();
            batchTiming.ApplyStageElapsed = applyStopwatch.Elapsed;
        }

        private void RemoveDeletedLavaApprovalSources( SqlConnection connection, LavaApprovalScanTarget target )
        {
            using ( var command = connection.CreateCommand() )
            {
                command.CommandText = target.GetRemoveDeletedSourcesSql();
                command.ExecuteNonQuery();
            }
        }

        private List<LavaApprovalScanTarget> GetLavaApprovalScanTargets()
        {
            return new List<LavaApprovalScanTarget>
            {
                new LavaApprovalScanTarget(
                    "AttributeValue",
                    "Value",
                    "CONVERT(bigint, t.[ValueChecksum])",
                    @"AttributeId IN (SELECT
	                    [Attribute].[Id]
                    FROM [Attribute]
                    INNER JOIN FieldType ON Attribute.FieldTypeId = FieldType.Id
                    WHERE ([Attribute].[Name] LIKE '%sql%'
                    OR [Attribute].[Name] LIKE '%Lava%'
                    OR [Attribute].[Name] LIKE '%Query%'
                    OR [Attribute].[Guid] = '01C9BA59-D8D4-4137-90A6-B3C06C70BBC3')
                    -- Things to ignore
                    AND [Attribute].[Key] NOT IN ('QueryTimeoutSeconds','CommandTimeoutSeconds','SqlCommandTimeout','SaveSQLForDebug')
                    AND [FieldType].[Name] NOT IN ('Boolean', 'Lava Commands')
                    AND [Attribute].[Guid] NOT IN (
	                    '234AD1B4-E4BA-4542-9422-AD3DACAEA890' -- IIS Log Query 'QueryParams'
	                    ,'B6EBBBE8-2EC7-4C18-BD82-82510445D5C9' -- Obsidian Dynamic Data 'QueryParams'
	                    ,'0D7A45A6-C885-44CD-9FA9-B8F431D943B5' -- Dynamic Chart 'QueryParams'
	                    ,'B0EC41B9-37C0-48FD-8E4E-37A8CA305012' -- Dynamic Data 'QueryParams'
                    ))",
                    true ),
                new LavaApprovalScanTarget(
                    "HtmlContent",
                    "Content",
                    "CONVERT(bigint, SUBSTRING(HASHBYTES('MD5', CONVERT(nvarchar(max), ISNULL(t.[Content], N''))), 1, 8))",
                    null,
                    true ),
                new LavaApprovalScanTarget(
                    "Block",
                    "PreHtml",
                    "CONVERT(bigint, SUBSTRING(HASHBYTES('MD5', CONVERT(nvarchar(max), ISNULL(t.[PreHtml], N''))), 1, 8))",
                    null,
                    true ),
                 new LavaApprovalScanTarget(
                    "Block",
                    "PostHtml",
                    "CONVERT(bigint, SUBSTRING(HASHBYTES('MD5', CONVERT(nvarchar(max), ISNULL(t.[PostHtml], N''))), 1, 8))",
                    null,
                    true ),
                 new LavaApprovalScanTarget(
                    "LavaShortcode",
                    "Markup",
                    "CONVERT(bigint, SUBSTRING(HASHBYTES('MD5', CONVERT(nvarchar(max), ISNULL(t.[Markup], N''))), 1, 8))",
                    null,
                    true ),
                 new LavaApprovalScanTarget(
                    "ContentChannelItem",
                    "Content",
                    "CONVERT(bigint, SUBSTRING(HASHBYTES('MD5', CONVERT(nvarchar(max), ISNULL(t.[Content], N''))), 1, 8))",
                    null,
                    true )
            };
        }

        private bool ContainsApprovalRequiredLava( string content )
        {
            if ( content.IsNullOrWhiteSpace() )
            {
                return false;
            }

            return ContainsLavaFormatting( content ) || ContainsLavaCommands( content );
        }

        private static bool ContainsLavaFormatting( string value )
        {
            return value.IndexOf( "{{", StringComparison.Ordinal ) >= 0;
        }

        private static bool ContainsLavaCommands( string value )
        {
            var length = value.Length - 1;

            for ( int i = 0; i < length; i++ )
            {
                if ( value[i] == '{' )
                {
                    var next = value[i + 1];

                    if ( next == '%' || next == '[' )
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private string ComputeContentHash( string content )
        {
            using ( var sha256 = SHA256.Create() )
            {
                var hashBytes = sha256.ComputeHash( Encoding.UTF8.GetBytes( content ?? string.Empty ) );
                return string.Concat( hashBytes.Select( b => b.ToString( "x2" ) ) );
            }
        }

        private string BuildLavaContentPreview( string content )
        {
            var preview = ( content ?? string.Empty ).Replace( "\r", " " ).Replace( "\n", " " ).Trim();
            while ( preview.Contains( "  " ) )
            {
                preview = preview.Replace( "  ", " " );
            }

            return preview.Length > 500 ? preview.Substring( 0, 500 ) + "..." : preview;
        }

        private AuditCheckResult AuditSecurityPluginVersion()
        {
            var rockVersion = Rock.VersionInfo.VersionInfo.GetRockSemanticVersionNumber();
            var details = new StringBuilder();
            var notices = new List<string>();

            try
            {
                var versionsJson = DownloadSecurityPluginVersionsJson( );
                var serializer = new JavaScriptSerializer();
                var versionData = serializer.DeserializeObject( versionsJson ) as Dictionary<string, object>;

                if ( versionData == null )
                {
                    return new AuditCheckResult
                    {
                        Name = "Security Plugin Version",
                        IsPassing = false,
                        Summary = "Security Plugin Version: the latest available security plugin version could not be determined.",
                        Details = "The security plugin versions could not be downloaded."
                    };
                }

                var latestPluginVersion = GetLatestSecurityPluginVersion( versionData, rockVersion );
                notices = GetSecurityPluginNotices( versionData, rockVersion );

                if ( latestPluginVersion.IsNullOrWhiteSpace() )
                {
                    details.AppendFormat( "No latest security plugin version was published for Rock version {0}.", rockVersion );

                    return new AuditCheckResult
                    {
                        Name = "Security Plugin Version",
                        IsPassing = false,
                        Summary = string.Format( "Security Plugin Version: no latest plugin version was found for Rock {0}.", rockVersion ),
                        Details = details.ToString(),
                        SecurityNotices = notices
                    };
                }

                var isCurrent = CompareVersions( SecurityPluginVersion, latestPluginVersion ) >= 0;
                details.AppendFormat( "Rock version: {0}. Installed security plugin version: {1}. Latest security plugin version: {2}.", rockVersion, SecurityPluginVersion, latestPluginVersion );

                return new AuditCheckResult
                {
                    Name = "Security Plugin Version",
                    IsPassing = isCurrent,
                    Summary = isCurrent
                        ? string.Format( "Security Plugin Version: installed version {0} is current for Rock {1}.", SecurityPluginVersion, rockVersion )
                        : string.Format( "Security Plugin Version: installed version {0} is older than latest version {1} for Rock {2}.", SecurityPluginVersion, latestPluginVersion, rockVersion ),
                    Details = isCurrent ? string.Empty : details.ToString(),
                    SecurityNotices = notices
                };
            }
            catch ( Exception ex )
            {
                return new AuditCheckResult
                {
                    Name = "Security Plugin Version",
                    IsPassing = false,
                    Summary = "Security Plugin Version: the latest available security plugin version could not be checked.",
                    Details = "The security plugin versions could not be downloaded or there was an error parsing the file.",
                    SecurityNotices = notices
                };
            }
        }

        private string DownloadSecurityPluginVersionsJson( )
        {
            var url = string.Format( "{0}", SecurityPluginVersionsUrl );
            var request = ( System.Net.HttpWebRequest )System.Net.WebRequest.Create( url );
            request.Method = "GET";
            request.Timeout = 3000;
            request.ReadWriteTimeout = 3000;

            using ( var response = ( System.Net.HttpWebResponse )request.GetResponse() )
            using ( var responseStream = response.GetResponseStream() )
            using ( var reader = new StreamReader( responseStream ) )
            {
                return reader.ReadToEnd();
            }
        }

        private string GetLatestSecurityPluginVersion( Dictionary<string, object> versionData, string rockVersion )
        {
            if ( versionData.ContainsKey( rockVersion ) )
            {
                return Convert.ToString( versionData[rockVersion] );
            }

            return string.Empty;
        }

        private List<string> GetSecurityPluginNotices( Dictionary<string, object> versionData, string rockVersion )
        {
            if ( !versionData.ContainsKey( "notices" ) )
            {
                return new List<string>();
            }

            var noticesByRockVersion = versionData["notices"] as Dictionary<string, object>;
            if ( noticesByRockVersion == null || !noticesByRockVersion.ContainsKey( rockVersion ) )
            {
                return new List<string>();
            }

            return GetNoticeMessages( noticesByRockVersion[rockVersion] );
        }

        private List<string> GetNoticeMessages( object noticesValue )
        {
            if ( noticesValue == null )
            {
                return new List<string>();
            }

            var noticeList = noticesValue as object[];
            if ( noticeList != null )
            {
                return noticeList.Select( n => Convert.ToString( n ) ).Where( n => n.IsNotNullOrWhiteSpace() ).ToList();
            }

            var notice = Convert.ToString( noticesValue );
            return notice.IsNotNullOrWhiteSpace()
                ? new List<string> { notice }
                : new List<string>();
        }

        private int CompareVersions( string installedVersion, string latestVersion )
        {
            Version installed;
            Version latest;

            if ( Version.TryParse( installedVersion, out installed ) && Version.TryParse( latestVersion, out latest ) )
            {
                return installed.CompareTo( latest );
            }

            return string.Compare( installedVersion, latestVersion, StringComparison.OrdinalIgnoreCase );
        }

        private AuditCheckResult AuditDisablePredictableIds()
        {
            var securitySettings = new SecuritySettingsService().SecuritySettings;
            var disablePredictableIds = securitySettings?.DisablePredictableIds == true;

            return new AuditCheckResult
            {
                Name = "Disable Predictable Ids",
                IsPassing = disablePredictableIds,
                Summary = disablePredictableIds
                    ? "Disable Predictable Ids: Rock SecuritySettings DisablePredictableIds is enabled."
                    : "Disable Predictable Ids: Rock SecuritySettings DisablePredictableIds is not enabled.",
                Details = disablePredictableIds
                    ? string.Empty
                    : "Enable DisablePredictableIds in Rock security settings to prevent predictable integer identifiers from being accepted."
            };
        }

        private AuditCheckResult AuditPasswordRegularExpression()
        {
            const string passwordRegularExpressionKey = "PasswordRegularExpression";
            const string weakDefaultPasswordRegularExpression = @"\w{6,255}";

            var passwordRegularExpression = GlobalAttributesCache.Get().GetValue( passwordRegularExpressionKey );
            var isMissing = passwordRegularExpression.IsNullOrWhiteSpace();
            var isWeakDefault = passwordRegularExpression == weakDefaultPasswordRegularExpression;

            return new AuditCheckResult
            {
                Name = "Password Regular Expression",
                IsPassing = !isMissing && !isWeakDefault,
                Summary = isWeakDefault
                    ? "Password Regular Expression: Global attribute is still the weak Rock default of \\w{6,255}."
                    : isMissing
                        ? "Password Regular Expression: Global attribute is blank, so Rock password regex validation is disabled."
                        : "Password Regular Expression: Global attribute is not the weak Rock default.",
                Details = isWeakDefault || isMissing
                    ? "Update the Password Regular Expression global attribute to enforce a stronger password policy."
                    : string.Empty
            };
        }

        private AuditCheckResult AuditAccountProtectionProfileSettings( RockContext rockContext )
        {
            var securitySettings = new SecuritySettingsService().SecuritySettings;
            var disablesTokensForExtremeProfile = securitySettings?.DisableTokensForAccountProtectionProfiles?.Contains( AccountProtectionProfile.Extreme ) == true;

            var administratorsGroup = new GroupService( rockContext ).Get( Rock.SystemGuid.Group.GROUP_ADMINISTRATORS.AsGuid() );
            var administratorsGroupHasExtremeProtectionProfile = administratorsGroup?.ElevatedSecurityLevel == ElevatedSecurityLevel.Extreme;

            var details = new StringBuilder();

            if ( !disablesTokensForExtremeProfile )
            {
                details.AppendLine( "Enable 'Disable Usage of Personal Tokens' for the Extreme account protection profile in Rock security settings." );
            }

            if ( administratorsGroup == null )
            {
                details.AppendLine( "The built-in Rock Administrators role could not be found." );
            }
            else if ( !administratorsGroupHasExtremeProtectionProfile )
            {
                details.AppendFormat(
                    "Set the Rock Administrators role (RSR - Rock Administration, Guid: {0}) protection profile to Extreme. Current value: {1}.",
                    Rock.SystemGuid.Group.GROUP_ADMINISTRATORS,
                    administratorsGroup.ElevatedSecurityLevel );
            }

            return new AuditCheckResult
            {
                Name = "Account Protection Profile Settings",
                IsPassing = disablesTokensForExtremeProfile && administratorsGroupHasExtremeProtectionProfile,
                Summary = disablesTokensForExtremeProfile && administratorsGroupHasExtremeProtectionProfile
                    ? "Account Protection Profile Settings: Extreme personal tokens are disabled and Rock Administrators has the Extreme protection profile."
                    : "Account Protection Profile Settings: Extreme personal tokens are not disabled or Rock Administrators does not have the Extreme protection profile.",
                Details = details.ToString()
            };
        }

        private AuditCheckResult AuditSecurityRoleMemberships( RockContext rockContext )
        {
            var roleAuditTargets = new List<RoleAuditTarget>
            {
                new RoleAuditTarget( "Rock Administrators", Rock.SystemGuid.Group.GROUP_ADMINISTRATORS ),
                new RoleAuditTarget( "Staff Workers", Rock.SystemGuid.Group.GROUP_STAFF_MEMBERS ),
                new RoleAuditTarget( "Staff-Like Workers", Rock.SystemGuid.Group.GROUP_STAFF_LIKE_MEMBERS )
            };

            var currentMemberships = GetSecurityRoleMemberships( rockContext, roleAuditTargets );
            var currentSnapshot = BuildSecurityRoleMembershipSnapshot( roleAuditTargets, currentMemberships );
            var previousSnapshot = Rock.Web.SystemSettings.GetValue( SecurityRoleMembershipSnapshotSystemSettingKey );
            var hasPreviousSnapshot = previousSnapshot.IsNotNullOrWhiteSpace();
            var previousMemberships = hasPreviousSnapshot
                ? ParseSecurityRoleMembershipSnapshot( previousSnapshot )
                : new Dictionary<string, HashSet<string>>();

            var currentMembershipsByRole = currentMemberships
                .GroupBy( m => m.RoleGuid )
                .ToDictionary( g => g.Key, g => new HashSet<string>( g.Select( m => m.PersonGuid ) ) );

            var memberNamesByGuid = GetSecurityRoleMemberNamesByGuid( rockContext, currentMemberships, previousMemberships );

            var details = new StringBuilder();
            var roleMembershipChanges = new List<RoleMembershipChange>();
            var hasChanges = !hasPreviousSnapshot;

            if ( !hasPreviousSnapshot )
            {
                details.AppendLine( "No previous security role membership snapshot existed; all current members are being reported as new." );
            }

            foreach ( var roleAuditTarget in roleAuditTargets )
            {
                var roleGuid = roleAuditTarget.RoleGuid.ToUpperInvariant();
                var currentPersonGuids = currentMembershipsByRole.ContainsKey( roleGuid )
                    ? currentMembershipsByRole[roleGuid]
                    : new HashSet<string>();
                var previousPersonGuids = hasPreviousSnapshot && previousMemberships.ContainsKey( roleGuid )
                    ? previousMemberships[roleGuid]
                    : new HashSet<string>();
                var addedPersonGuids = currentPersonGuids.Except( previousPersonGuids ).OrderBy( g => g ).ToList();
                var removedPersonGuids = previousPersonGuids.Except( currentPersonGuids ).OrderBy( g => g ).ToList();

                if ( addedPersonGuids.Any() || removedPersonGuids.Any() )
                {
                    hasChanges = true;
                    details.AppendLine();
                    details.AppendFormat( "{0} changed.", roleAuditTarget.Name );
                    details.AppendLine();

                    AppendSecurityRoleMembershipChangeDetails( details, "Added", addedPersonGuids, memberNamesByGuid );
                    AppendSecurityRoleMembershipChangeDetails( details, "Removed", removedPersonGuids, memberNamesByGuid );
                    AddSecurityRoleMembershipChanges( roleMembershipChanges, roleAuditTarget.Name, "Added", addedPersonGuids, memberNamesByGuid );
                    AddSecurityRoleMembershipChanges( roleMembershipChanges, roleAuditTarget.Name, "Removed", removedPersonGuids, memberNamesByGuid );
                }
            }

            Rock.Web.SystemSettings.SetValue(
                SecurityRoleMembershipSnapshotSystemSettingKey,
                currentSnapshot,
                SecurityRoleMembershipSnapshotSystemSettingGuid.AsGuid() );

            return new AuditCheckResult
            {
                Name = "Security Role Memberships",
                IsPassing = !hasChanges,
                Summary = hasChanges
                    ? "Security Role Memberships: administrator, staff, or staff-like worker role membership changed since the previous audit run."
                    : "Security Role Memberships: administrator, staff, and staff-like worker role membership is unchanged since the previous audit run.",
                Details = details.ToString(),
                RoleMembershipChanges = roleMembershipChanges
            };
        }

        private List<SecurityRoleMembership> GetSecurityRoleMemberships( RockContext rockContext, List<RoleAuditTarget> roleAuditTargets )
        {
            var roleGuids = roleAuditTargets.Select( r => r.RoleGuid.AsGuid() ).ToList();

            return new GroupMemberService( rockContext ).Queryable()
                .Where( m => roleGuids.Contains( m.Group.Guid ) && m.GroupMemberStatus == GroupMemberStatus.Active )
                .Select( m => new
                {
                    RoleGuid = m.Group.Guid,
                    PersonGuid = m.Person.Guid
                } )
                .ToList()
                .Select( m => new SecurityRoleMembership
                {
                    RoleGuid = m.RoleGuid.ToString().ToUpperInvariant(),
                    PersonGuid = m.PersonGuid.ToString().ToUpperInvariant()
                } )
                .OrderBy( m => m.RoleGuid )
                .ThenBy( m => m.PersonGuid )
                .ToList();
        }

        private string BuildSecurityRoleMembershipSnapshot( List<RoleAuditTarget> roleAuditTargets, List<SecurityRoleMembership> memberships )
        {
            var membershipsByRole = memberships
                .GroupBy( m => m.RoleGuid )
                .ToDictionary( g => g.Key, g => g.Select( m => m.PersonGuid ).OrderBy( p => p ).ToList() );

            return string.Join(
                System.Environment.NewLine,
                roleAuditTargets
                    .Select( r => r.RoleGuid.ToUpperInvariant() )
                    .OrderBy( g => g )
                    .Select( g => string.Format( "{0}|{1}", g, membershipsByRole.ContainsKey( g ) ? string.Join( ",", membershipsByRole[g] ) : string.Empty ) ) );
        }

        private Dictionary<string, string> GetSecurityRoleMemberNamesByGuid(
            RockContext rockContext,
            List<SecurityRoleMembership> currentMemberships,
            Dictionary<string, HashSet<string>> previousMemberships )
        {
            var personGuids = currentMemberships
                .Select( m => m.PersonGuid )
                .Concat( previousMemberships.SelectMany( m => m.Value ) )
                .Distinct()
                .Select( g => g.AsGuid() )
                .ToList();

            return new PersonService( rockContext ).Queryable()
                .Where( p => personGuids.Contains( p.Guid ) )
                .Select( p => new
                {
                    p.Guid,
                    p.NickName,
                    p.LastName
                } )
                .ToList()
                .ToDictionary(
                    p => p.Guid.ToString().ToUpperInvariant(),
                    p => string.Format( "{0} {1}", p.NickName, p.LastName ).Trim() );
        }

        private Dictionary<string, HashSet<string>> ParseSecurityRoleMembershipSnapshot( string snapshot )
        {
            var membershipsByRole = new Dictionary<string, HashSet<string>>();
            var lines = snapshot.Split( new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries );

            foreach ( var line in lines )
            {
                var parts = line.Split( new[] { '|' }, 2 );
                if ( parts.Length != 2 )
                {
                    continue;
                }

                membershipsByRole[parts[0].Trim().ToUpperInvariant()] = new HashSet<string>(
                    parts[1]
                        .Split( new[] { ',' }, StringSplitOptions.RemoveEmptyEntries )
                        .Select( p => p.Trim().ToUpperInvariant() ) );
            }

            return membershipsByRole;
        }

        private void AppendSecurityRoleMembershipChangeDetails( StringBuilder details, string label, List<string> personGuids, Dictionary<string, string> memberNamesByGuid )
        {
            if ( !personGuids.Any() )
            {
                return;
            }

            details.AppendFormat( "{0}: {1}.", label, string.Join( "; ", personGuids.Select( g => FormatSecurityRoleMember( g, memberNamesByGuid ) ) ) );
            details.AppendLine();
        }

        private void AddSecurityRoleMembershipChanges( List<RoleMembershipChange> roleMembershipChanges, string roleName, string changeType, List<string> personGuids, Dictionary<string, string> memberNamesByGuid )
        {
            foreach ( var personGuid in personGuids )
            {
                roleMembershipChanges.Add( new RoleMembershipChange
                {
                    RoleName = roleName,
                    ChangeType = changeType,
                    PersonName = memberNamesByGuid.ContainsKey( personGuid ) ? memberNamesByGuid[personGuid] : string.Empty,
                    PersonGuid = personGuid
                } );
            }
        }

        private string FormatSecurityRoleMember( string personGuid, Dictionary<string, string> memberNamesByGuid )
        {
            if ( memberNamesByGuid.ContainsKey( personGuid ) && memberNamesByGuid[personGuid].IsNotNullOrWhiteSpace() )
            {
                return string.Format( "{0} ({1})", memberNamesByGuid[personGuid], personGuid );
            }

            return personGuid;
        }

        private void SendResultsEmail( string notificationEmails, List<AuditCheckResult> checkResults, int passingCheckCount )
        {
            var recipients = notificationEmails.SplitDelimitedValues()
                .Select( e => RockEmailMessageRecipient.CreateAnonymous( e, null ) )
                .ToList();

            if ( !recipients.Any() )
            {
                return;
            }

            var emailMessage = new RockEmailMessage();
            emailMessage.Subject = checkResults.All( c => c.IsPassing ) ? "Security Audit: Passed" : "Security Audit: Failed";
            emailMessage.Message = BuildHtmlMessage( checkResults, passingCheckCount );
            emailMessage.PlainTextMessage = Result;
            emailMessage.CreateCommunicationRecord = false;
            emailMessage.SetRecipients( recipients );

            var errors = new List<string>();
            emailMessage.Send( out errors );

            if ( errors.Any() )
            {
                Result += string.Format( "{0}{0}Email errors:{0}{1}", System.Environment.NewLine, string.Join( System.Environment.NewLine, errors ) );
            }
        }

        private string BuildHtmlMessage( List<AuditCheckResult> checkResults, int passingCheckCount )
        {
            var html = new StringBuilder();
            html.Append( "<h2>Security Audit</h2>" );
            html.AppendFormat( "<p><strong>{0} of {1}</strong> security audit checks passed.</p>", passingCheckCount, checkResults.Count );
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;margin-bottom:24px;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>Check</th><th align='left' style='border-bottom:1px solid #ddd;'>Status</th><th align='left' style='border-bottom:1px solid #ddd;'>Summary</th></tr></thead><tbody>" );

            foreach ( var checkResult in checkResults )
            {
                html.AppendFormat(
                    "<tr><td style='border-bottom:1px solid #eee;'>{0}</td><td style='border-bottom:1px solid #eee;'>{1}</td><td style='border-bottom:1px solid #eee;'>{2}</td></tr>",
                    HttpUtility.HtmlEncode( checkResult.Name ),
                    BuildStatusBadgeHtml( checkResult.IsPassing ),
                    HttpUtility.HtmlEncode( checkResult.Summary ) );
            }

            html.Append( "</tbody></table>" );

            html.Append( BuildSecurityNoticesHtml( checkResults ) );

            foreach ( var checkResult in checkResults )
            {
                if ( checkResult.IsPassing == false && checkResult.Name != "Lava Approvals" )
                {
                    html.AppendFormat( "<h3>{0}</h3>", HttpUtility.HtmlEncode( checkResult.Name ) );

                    if ( checkResult.Name == "Binary File Type Security" )
                    {
                        html.Append( BuildBinaryFileTypeDetailsHtml( checkResult.InsecureFileTypes ) );
                    }
                    else if ( checkResult.Name == "Document Type Security" )
                    {
                        html.Append( BuildDocumentTypeDetailsHtml( checkResult.InsecureDocumentTypes ) );
                    }
                    else if ( checkResult.Name == "Workflow Security" )
                    {
                        html.Append( BuildWorkflowSecurityDetailsHtml( checkResult.InsecureWorkflowEntryBlocks, checkResult.InsecureWorkflowTypes ) );
                    }
                    else if ( checkResult.Name == "Add Person To Group Workflow Security" )
                    {
                        html.Append( BuildWorkflowTypeDetailsHtml( checkResult.InsecureWorkflowTypes ) );
                    }
                    else if ( checkResult.Name == "Security Role Memberships" )
                    {
                        html.Append( BuildSecurityRoleMembershipDetailsHtml( checkResult.RoleMembershipChanges, checkResult.Details ) );
                    }
                    else if ( checkResult.Name == "SQL Injection Content" )
                    {
                        html.Append( BuildSqlInjectionContentDetailsHtml( checkResult.SqlInjectionContentFindings ) );
                    }
                    else if ( checkResult.Details.IsNotNullOrWhiteSpace() )
                    {
                        html.AppendFormat( "<p>{0}</p>", HttpUtility.HtmlEncode( checkResult.Details ) );
                    }
                }
            }

            return html.ToString();
        }

        private string BuildStatusBadgeHtml( bool isPassing )
        {
            return isPassing
                ? "<span style='display:inline-block;background-color:#28a745;color:#fff;border-radius:4px;padding:3px 8px;font-weight:bold;'>Pass</span>"
                : "<span style='display:inline-block;background-color:#dc3545;color:#fff;border-radius:4px;padding:3px 8px;font-weight:bold;'>Fail</span>";
        }

        private string BuildSecurityNoticesHtml( List<AuditCheckResult> checkResults )
        {
            var notices = checkResults
                .Where( c => c.SecurityNotices != null )
                .SelectMany( c => c.SecurityNotices )
                .Where( n => n.IsNotNullOrWhiteSpace() )
                .ToList();

            if ( !notices.Any() )
            {
                return string.Empty;
            }

            var html = new StringBuilder();
            html.Append( "<h3>Security Notices</h3>" );
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;margin-bottom:24px;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>Notice</th></tr></thead><tbody>" );

            foreach ( var notice in notices )
            {
                html.AppendFormat( "<tr><td style='border-bottom:1px solid #eee;'>{0}</td></tr>", notice );
            }

            html.Append( "</tbody></table>" );
            return html.ToString();
        }

        private string BuildBinaryFileTypeDetailsHtml( List<FileTypeAuditResult> insecureFileTypes )
        {
            if ( !insecureFileTypes.Any() )
            {
                return "<p>No insecure binary file types were found.</p>";
            }

            var html = new StringBuilder();
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>File Type</th><th align='right' style='border-bottom:1px solid #ddd;'>Binary Files</th><th align='left' style='border-bottom:1px solid #ddd;'>Reasons</th><th align='left' style='border-bottom:1px solid #ddd;'>Guid</th></tr></thead><tbody>" );

            foreach ( var fileType in insecureFileTypes )
            {
                html.AppendFormat(
                    "<tr><td style='border-bottom:1px solid #eee;'>{0}</td><td align='right' style='border-bottom:1px solid #eee;'>{1}</td><td style='border-bottom:1px solid #eee;'>{2}</td><td style='border-bottom:1px solid #eee;'>{3}</td></tr>",
                    HttpUtility.HtmlEncode( fileType.Name ),
                    fileType.FileCount,
                    HttpUtility.HtmlEncode( string.Join( "; ", fileType.Reasons ) ),
                    HttpUtility.HtmlEncode( fileType.Guid ) );
            }

            html.Append( "</tbody></table>" );
            return html.ToString();
        }

        private string BuildDocumentTypeDetailsHtml( List<DocumentTypeAuditResult> insecureDocumentTypes )
        {
            if ( !insecureDocumentTypes.Any() )
            {
                return "<p>No insecure document types were found.</p>";
            }

            var html = new StringBuilder();
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>Document Type</th><th align='left' style='border-bottom:1px solid #ddd;'>Entity Type</th><th align='right' style='border-bottom:1px solid #ddd;'>Documents</th><th align='left' style='border-bottom:1px solid #ddd;'>Reasons</th><th align='left' style='border-bottom:1px solid #ddd;'>Guid</th></tr></thead><tbody>" );

            foreach ( var documentType in insecureDocumentTypes )
            {
                html.AppendFormat(
                    "<tr><td style='border-bottom:1px solid #eee;'>{0}</td><td style='border-bottom:1px solid #eee;'>{1}</td><td align='right' style='border-bottom:1px solid #eee;'>{2}</td><td style='border-bottom:1px solid #eee;'>{3}</td><td style='border-bottom:1px solid #eee;'>{4}</td></tr>",
                    HttpUtility.HtmlEncode( documentType.Name ),
                    HttpUtility.HtmlEncode( documentType.EntityType ),
                    documentType.DocumentCount,
                    HttpUtility.HtmlEncode( string.Join( "; ", documentType.Reasons ) ),
                    HttpUtility.HtmlEncode( documentType.Guid ) );
            }

            html.Append( "</tbody></table>" );
            return html.ToString();
        }

        private string BuildWorkflowSecurityDetailsHtml( List<WorkflowEntryBlockAuditResult> insecureWorkflowEntryBlocks, List<WorkflowTypeAuditResult> insecureWorkflowTypes )
        {
            var html = new StringBuilder();

            html.Append( "<h4>Exposed Workflow Entry Blocks Without Workflow Type</h4>" );
            html.Append( BuildWorkflowEntryBlockDetailsHtml( insecureWorkflowEntryBlocks ) );
            html.Append( "<h4>Public Workflow Types</h4>" );
            html.Append( BuildWorkflowTypeDetailsHtml( insecureWorkflowTypes ) );

            return html.ToString();
        }

        private string BuildWorkflowEntryBlockDetailsHtml( List<WorkflowEntryBlockAuditResult> insecureWorkflowEntryBlocks )
        {
            if ( insecureWorkflowEntryBlocks == null || !insecureWorkflowEntryBlocks.Any() )
            {
                return "<p>No exposed workflow entry blocks without Workflow Type were found.</p>";
            }

            var html = new StringBuilder();
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;margin-bottom:16px;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>Block</th><th align='left' style='border-bottom:1px solid #ddd;'>Block Type</th><th align='left' style='border-bottom:1px solid #ddd;'>Page</th><th align='left' style='border-bottom:1px solid #ddd;'>Block Guid</th><th align='left' style='border-bottom:1px solid #ddd;'>Page Id</th></tr></thead><tbody>" );

            foreach ( var block in insecureWorkflowEntryBlocks )
            {
                html.AppendFormat(
                    "<tr><td style='border-bottom:1px solid #eee;'>{0}</td><td style='border-bottom:1px solid #eee;'>{1}</td><td style='border-bottom:1px solid #eee;'>{2}</td><td style='border-bottom:1px solid #eee;'>{3}</td><td style='border-bottom:1px solid #eee;'>{4}</td></tr>",
                    HttpUtility.HtmlEncode( block.Name ),
                    HttpUtility.HtmlEncode( block.BlockType ),
                    HttpUtility.HtmlEncode( block.PageName ),
                    HttpUtility.HtmlEncode( block.Guid ),
                    HttpUtility.HtmlEncode( block.PageId ) );
            }

            html.Append( "</tbody></table>" );
            return html.ToString();
        }

        private string BuildWorkflowTypeDetailsHtml( List<WorkflowTypeAuditResult> insecureWorkflowTypes )
        {
            if ( insecureWorkflowTypes == null || !insecureWorkflowTypes.Any() )
            {
                return "<p>No insecure workflow types were found.</p>";
            }

            var html = new StringBuilder();
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>Workflow Type</th><th align='left' style='border-bottom:1px solid #ddd;'>Reasons</th><th align='left' style='border-bottom:1px solid #ddd;'>Guid</th></tr></thead><tbody>" );

            foreach ( var workflowType in insecureWorkflowTypes )
            {
                html.AppendFormat(
                    "<tr><td style='border-bottom:1px solid #eee;'>{0}</td><td style='border-bottom:1px solid #eee;'>{1}</td><td style='border-bottom:1px solid #eee;'>{2}</td></tr>",
                    HttpUtility.HtmlEncode( workflowType.Name ),
                    HttpUtility.HtmlEncode( string.Join( "; ", workflowType.Reasons ) ),
                    HttpUtility.HtmlEncode( workflowType.Guid ) );
            }

            html.Append( "</tbody></table>" );
            return html.ToString();
        }

        private string BuildSecurityRoleMembershipDetailsHtml( List<RoleMembershipChange> roleMembershipChanges, string details )
        {
            if ( roleMembershipChanges == null || !roleMembershipChanges.Any() )
            {
                return details.IsNotNullOrWhiteSpace()
                    ? string.Format( "<p>{0}</p>", HttpUtility.HtmlEncode( details ) )
                    : "<p>No role membership changes were found.</p>";
            }

            var html = new StringBuilder();
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>Role</th><th align='left' style='border-bottom:1px solid #ddd;'>Change</th><th align='left' style='border-bottom:1px solid #ddd;'>Person</th><th align='left' style='border-bottom:1px solid #ddd;'>Person Guid</th></tr></thead><tbody>" );

            foreach ( var roleMembershipChange in roleMembershipChanges )
            {
                html.AppendFormat(
                    "<tr><td style='border-bottom:1px solid #eee;'>{0}</td><td style='border-bottom:1px solid #eee;'>{1}</td><td style='border-bottom:1px solid #eee;'>{2}</td><td style='border-bottom:1px solid #eee;'>{3}</td></tr>",
                    HttpUtility.HtmlEncode( roleMembershipChange.RoleName ),
                    HttpUtility.HtmlEncode( roleMembershipChange.ChangeType ),
                    HttpUtility.HtmlEncode( roleMembershipChange.PersonName ),
                    HttpUtility.HtmlEncode( roleMembershipChange.PersonGuid ) );
            }

            html.Append( "</tbody></table>" );
            return html.ToString();
        }

        private string BuildSqlInjectionContentDetailsHtml( List<SqlInjectionContentFinding> findings )
        {
            if ( findings == null || !findings.Any() )
            {
                return "<p>No Person or Location rows containing '&lt;script' were found.</p>";
            }

            var html = new StringBuilder();
            html.Append( "<table cellpadding='8' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;'>" );
            html.Append( "<thead><tr><th align='left' style='border-bottom:1px solid #ddd;'>Table</th><th align='right' style='border-bottom:1px solid #ddd;'>Id</th></tr></thead><tbody>" );

            foreach ( var finding in findings.OrderBy( f => f.TableName ).ThenBy( f => f.Id ) )
            {
                html.AppendFormat(
                    "<tr><td style='border-bottom:1px solid #eee;'>{0}</td><td align='right' style='border-bottom:1px solid #eee;'>{1}</td></tr>",
                    HttpUtility.HtmlEncode( finding.TableName ),
                    finding.Id );
            }

            html.Append( "</tbody></table>" );
            return html.ToString();
        }

        private class AuditCheckResult
        {
            public string Name { get; set; }

            public bool IsPassing { get; set; }

            public string Summary { get; set; }

            public string Details { get; set; }

            public List<FileTypeAuditResult> InsecureFileTypes { get; set; }

            public List<DocumentTypeAuditResult> InsecureDocumentTypes { get; set; }

            public List<WorkflowEntryBlockAuditResult> InsecureWorkflowEntryBlocks { get; set; }

            public List<WorkflowTypeAuditResult> InsecureWorkflowTypes { get; set; }

            public List<RoleMembershipChange> RoleMembershipChanges { get; set; }

            public List<SqlInjectionContentFinding> SqlInjectionContentFindings { get; set; }

            public List<LavaApprovalFinding> LavaApprovalFindings { get; set; }

            public List<string> SecurityNotices { get; set; }
        }

        private class RoleAuditTarget
        {
            public RoleAuditTarget( string name, string roleGuid )
            {
                Name = name;
                RoleGuid = roleGuid;
            }

            public string Name { get; private set; }

            public string RoleGuid { get; private set; }
        }

        private class SecurityRoleMembership
        {
            public string RoleGuid { get; set; }

            public string PersonGuid { get; set; }
        }

        private class RoleMembershipChange
        {
            public string RoleName { get; set; }

            public string ChangeType { get; set; }

            public string PersonName { get; set; }

            public string PersonGuid { get; set; }
        }

        private class SqlInjectionContentFinding
        {
            public string TableName { get; set; }

            public int Id { get; set; }
        }

        private class LavaApprovalFinding
        {
            public string TableName { get; set; }

            public string ColumnName { get; set; }

            public int RowId { get; set; }

            public string ContentHash { get; set; }

            public string ContentPreview { get; set; }
        }

        private class LavaApprovalScanRow
        {
            public int RowId { get; set; }

            public long? SourceChecksum { get; set; }

            public string Content { get; set; }
        }

        private class LavaShortcodeScanContext
        {
            public int Id { get; set; }

            public string TagName { get; set; }
        }

        private class LavaApprovalScanBatchTiming
        {
            public int BatchNumber { get; set; }

            public int ChangedRowCount { get; set; }

            public int? WindowMaxRowId { get; set; }

            public int ExistingSourceCount { get; set; }

            public int NewSourceCount { get; set; }

            public int ApprovalRequiredLavaCount { get; set; }

            public int UnchangedApprovalRequiredLavaCount { get; set; }

            public TimeSpan ChangedRowsElapsed { get; set; }

            public TimeSpan ContainsLavaElapsed { get; set; }

            public TimeSpan ComputeHashElapsed { get; set; }

            public TimeSpan BuildPreviewElapsed { get; set; }

            public TimeSpan BulkCopyElapsed { get; set; }

            public TimeSpan ApplyStageElapsed { get; set; }

            public string Format( LavaApprovalScanTarget target )
            {
                return string.Format(
                    "{0}.{1} batch {2}: windowMaxRowId={3}, changedRows={4}, existingUpdated={5}, inserted={6}, approvalRequired={7}, unchangedApprovalRequired={8}; read source window={9} (contains lava={10}, hash={11}, preview={12}), bulk copy={13}, apply stage={14}.",
                    target.TableName,
                    target.ColumnName,
                    BatchNumber,
                    WindowMaxRowId.HasValue ? WindowMaxRowId.Value.ToString() : "none",
                    ChangedRowCount,
                    ExistingSourceCount,
                    NewSourceCount,
                    ApprovalRequiredLavaCount,
                    UnchangedApprovalRequiredLavaCount,
                    FormatElapsed( ChangedRowsElapsed ),
                    FormatElapsed( ContainsLavaElapsed ),
                    FormatElapsed( ComputeHashElapsed ),
                    FormatElapsed( BuildPreviewElapsed ),
                    FormatElapsed( BulkCopyElapsed ),
                    FormatElapsed( ApplyStageElapsed ) );
            }

            private string FormatElapsed( TimeSpan elapsed )
            {
                return string.Format( "{0:N0} ms", elapsed.TotalMilliseconds );
            }
        }

        private class LavaApprovalScanTarget
        {
            public LavaApprovalScanTarget( string tableName, string columnName, string sourceChecksumSql, string sourceWhereClauseSql = null, bool shouldCheckForApprovalRequiredLava = true )
            {
                TableName = tableName;
                ColumnName = columnName;
                SourceChecksumSql = sourceChecksumSql;
                SourceWhereClauseSql = sourceWhereClauseSql;
                ShouldCheckForApprovalRequiredLava = shouldCheckForApprovalRequiredLava;
            }

            public string TableName { get; private set; }

            public string ColumnName { get; private set; }

            public string SourceChecksumSql { get; private set; }

            public string SourceWhereClauseSql { get; private set; }

            public bool ShouldCheckForApprovalRequiredLava { get; private set; }

            public string GetMaxRowIdSql()
            {
                return string.Format( "SELECT ISNULL(MAX(t.[Id]), 0) FROM [dbo].[{0}] t WHERE 1 = 1{1}", TableName, GetSourceWhereConditionSql() );
            }

            public string GetChangedRowsSql( int batchSize )
            {
                return string.Format( @"
                    DECLARE @SourceRows TABLE (
                        [RowId] [int] PRIMARY KEY,
                        [SourceChecksum] [bigint] NULL,
                        [Content] [nvarchar](max) NULL
                    );

                    INSERT INTO @SourceRows
                    SELECT TOP ({3})
                        t.[Id],
                        {2},
                        t.[{1}]
                    FROM [dbo].[{0}] t {5}
                    WHERE t.[Id] > @AfterRowId
                        {4}
                    ORDER BY t.[Id] ASC;

                    SELECT
                        t.[RowId],
                        t.[SourceChecksum],
                        t.[Content]
                    FROM @SourceRows t
                    WHERE (
                        t.[Content] IS NOT NULL
                        AND NOT EXISTS (
                            SELECT 1
                            FROM [dbo].[_net_redeemertech_LavaApprovalSource] s
                            WHERE s.[TableName] = N'{0}'
                                AND s.[ColumnName] = N'{1}'
                                AND s.[RowId] = t.[RowId]
                                AND (
                                    s.[SourceChecksum] = t.[SourceChecksum]
                                    OR (s.[SourceChecksum] IS NULL AND t.[SourceChecksum] IS NULL)
                                )
                        )
                    )
                    OR (
                        t.[Content] IS NOT NULL
                        AND EXISTS (
                            SELECT 1
                            FROM [dbo].[_net_redeemertech_LavaApprovalSource] s
                            WHERE s.[TableName] = N'{0}'
                                AND s.[ColumnName] = N'{1}'
                                AND s.[RowId] = t.[RowId]
                                AND s.[HasApprovalRequiredLava] = 1
                                AND s.[ReferencedShortcodes] IS NULL
                                AND (
                                    s.[SourceChecksum] = t.[SourceChecksum]
                                    OR (s.[SourceChecksum] IS NULL AND t.[SourceChecksum] IS NULL)
                                )
                        )
                    )
                    OR (
                        t.[Content] IS NULL
                        AND EXISTS (
                            SELECT 1
                            FROM [dbo].[_net_redeemertech_LavaApprovalSource] s
                            WHERE s.[TableName] = N'{0}'
                                AND s.[ColumnName] = N'{1}'
                                AND s.[RowId] = t.[RowId]
                        )
                    )
                    ORDER BY t.[RowId] ASC;

                    SELECT MAX([RowId])
                    FROM @SourceRows;",
                    TableName,
                    ColumnName,
                    SourceChecksumSql,
                    batchSize,
                    GetSourceWhereConditionSql(),
                    TableName == "AttributeValue" ? "WITH (INDEX(IX_AttributeId))" : string.Empty );
            }

            public string GetRemoveDeletedSourcesSql()
            {
                return string.Format( @"
                    DELETE s
                    FROM [dbo].[_net_redeemertech_LavaApprovalSource] s
                    WHERE s.[TableName] = N'{0}'
                        AND s.[ColumnName] = N'{1}'
                        AND NOT EXISTS (
                            SELECT 1
                            FROM [dbo].[{0}] t
                            WHERE t.[Id] = s.[RowId]
                                {2}
                        )",
                    TableName,
                    ColumnName,
                    GetSourceWhereConditionSql() );
            }

            private string GetSourceWhereConditionSql()
            {
                if ( SourceWhereClauseSql.IsNullOrWhiteSpace() )
                {
                    return string.Empty;
                }

                var whereClause = SourceWhereClauseSql.Trim();
                if ( whereClause.StartsWith( "WHERE ", StringComparison.OrdinalIgnoreCase ) )
                {
                    whereClause = whereClause.Substring( 6 ).Trim();
                }

                return string.Format( " AND ({0})", whereClause );
            }
        }

        private class FileTypeAuditResult
        {
            public int Id { get; set; }

            public string Guid { get; set; }

            public string Name { get; set; }

            public bool RequiresViewSecurity { get; set; }

            public bool AllowsPublicView { get; set; }

            public bool AllowsAllAuthenticatedUsersView { get; set; }

            public int FileCount { get; set; }

            public bool IsSecure
            {
                get
                {
                    return RequiresViewSecurity && !AllowsPublicView && !AllowsAllAuthenticatedUsersView;
                }
            }

            public IEnumerable<string> Reasons
            {
                get
                {
                    if ( !RequiresViewSecurity )
                    {
                        yield return "Requires View Security is disabled";
                    }

                    if ( AllowsPublicView )
                    {
                        yield return "View is allowed to the public";
                    }

                    if ( AllowsAllAuthenticatedUsersView )
                    {
                        yield return "View is allowed to All Authenticated Users";
                    }
                }
            }
        }

        private class DocumentTypeAuditResult
        {
            public int Id { get; set; }

            public string Guid { get; set; }

            public string Name { get; set; }

            public string EntityType { get; set; }

            public bool AllowsPublicView { get; set; }

            public bool AllowsAllAuthenticatedUsersView { get; set; }

            public int DocumentCount { get; set; }

            public bool IsSecure
            {
                get
                {
                    return !AllowsPublicView && !AllowsAllAuthenticatedUsersView;
                }
            }

            public IEnumerable<string> Reasons
            {
                get
                {
                    if ( AllowsPublicView )
                    {
                        yield return "View is allowed to the public";
                    }

                    if ( AllowsAllAuthenticatedUsersView )
                    {
                        yield return "View is allowed to All Authenticated Users";
                    }
                }
            }
        }

        private class WorkflowEntryBlockAuditResult
        {
            public int Id { get; set; }

            public string Guid { get; set; }

            public string Name { get; set; }

            public string BlockType { get; set; }

            public int PageId { get; set; }

            public string PageGuid { get; set; }

            public string PageName { get; set; }
        }

        private class WorkflowTypeAuditResult
        {
            public int Id { get; set; }

            public string Guid { get; set; }

            public string Name { get; set; }

            public bool AllowsAllUsersView { get; set; }

            public bool AllowsAllAuthenticatedUsersView { get; set; }

            public bool IsSecure
            {
                get
                {
                    return !AllowsAllUsersView && !AllowsAllAuthenticatedUsersView;
                }
            }

            public IEnumerable<string> Reasons
            {
                get
                {
                    if ( AllowsAllUsersView )
                    {
                        yield return "View is allowed to All Users";
                    }

                    if ( AllowsAllAuthenticatedUsersView )
                    {
                        yield return "View is allowed to All Authenticated Users";
                    }
                }
            }
        }
    }
}
