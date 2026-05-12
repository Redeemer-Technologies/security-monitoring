using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Script.Serialization;

using Quartz;

using Rock;
using Rock.Attribute;
using Rock.Communication;
using Rock.Data;
using Rock.Jobs;
using Rock.Model;
using Rock.Security;
using Rock.Web.Cache;

namespace net.redeemertech.Security
{
    [DisplayName( "Security Audit" )]
    [Description( "Audits Rock security settings, security role membership, binary file type view permissions, and document type view permissions." )]
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
    [DisallowConcurrentExecution]
    public class SecurityAudit : RockJob
    {
        private const string SecurityPluginVersionsUrl = "https://security.redeemertech.com/security-plugin-versions.json";
        private const string SecurityRoleMembershipSnapshotSystemSettingKey = "net.redeemertech.SecurityAudit.SecurityRoleMembershipSnapshot";
        private const string SecurityRoleMembershipSnapshotSystemSettingGuid = "08e7a104-f535-4403-a73e-240cdf8daf49";

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
        }

        public override void Execute()
        {
            using ( var rockContext = new RockContext() )
            {
                var checkResults = new List<AuditCheckResult>
                {
                    AuditSecurityPluginVersion(),
                    AuditDisablePredictableIds(),
                    AuditPasswordRegularExpression(),
                    AuditSecurityRoleMemberships( rockContext ),
                    AuditSqlInjectionContent( rockContext ),
                    AuditBinaryFileTypeSecurity( rockContext ),
                    AuditDocumentTypeSecurity( rockContext )
                };

                var passingCheckCount = checkResults.Count( c => c.IsPassing );
                var jobResult = new StringBuilder();
                jobResult.AppendFormat( "{0} of {1} security audit checks passed.", passingCheckCount, checkResults.Count );

                foreach ( var checkResult in checkResults )
                {
                    jobResult.AppendLine();
                    jobResult.AppendLine();
                    jobResult.AppendLine( checkResult.Summary );

                    if ( checkResult.Details.IsNotNullOrWhiteSpace() )
                    {
                        jobResult.AppendLine( checkResult.Details );
                    }

                    if ( checkResult.SecurityNotices != null && checkResult.SecurityNotices.Any() )
                    {
                        jobResult.AppendLine( "Security Notices:" );
                        foreach ( var notice in checkResult.SecurityNotices )
                        {
                            jobResult.AppendLine( notice );
                        }
                    }
                }

                this.Result = jobResult.ToString();

                var notificationEmails = ServiceJob?.NotificationEmails;
                if ( notificationEmails.IsNotNullOrWhiteSpace() )
                {
                    SendResultsEmail( notificationEmails, checkResults, passingCheckCount );
                }
            }
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

        private AuditCheckResult AuditSqlInjectionContent( RockContext rockContext )
        {
            var findings = new List<SqlInjectionContentFinding>();

            findings.AddRange(
                rockContext.Database.SqlQuery<int>( @"
                    SELECT [Id]
                    FROM [Person]
                    WHERE [LastName] LIKE '%<script%'
                    OR [FirstName] LIKE '%<script%'
                    OR [NickName] LIKE '%<script%'" )
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
                Name = "SQL Injection Content",
                IsPassing = !findings.Any(),
                Summary = findings.Any()
                    ? string.Format( "SQL Injection Content: {0} Person or Location rows contain '<script'.", findings.Count )
                    : "SQL Injection Content: no Person or Location rows contain '<script'.",
                Details = details.ToString(),
                SqlInjectionContentFindings = findings
            };
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
                if (checkResult.IsPassing == false)
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

            public List<RoleMembershipChange> RoleMembershipChanges { get; set; }

            public List<SqlInjectionContentFinding> SqlInjectionContentFindings { get; set; }

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

        private class FileTypeAuditResult
        {
            public int Id { get; set; }

            public string Guid { get; set; }

            public string Name { get; set; }

            public bool RequiresViewSecurity { get; set; }

            public bool AllowsPublicView { get; set; }

            public int FileCount { get; set; }

            public bool IsSecure
            {
                get
                {
                    return RequiresViewSecurity && !AllowsPublicView;
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

            public int DocumentCount { get; set; }

            public bool IsSecure
            {
                get
                {
                    return !AllowsPublicView;
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
                }
            }
        }
    }
}
