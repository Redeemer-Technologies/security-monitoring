using net.redeemertech.Security.Model;

using Rock;
using Rock.Web.Cache;
using System;
using System.Collections.Generic;
using System.Linq;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class LavaApprovalBag
    {
        public string IdKey { get; set; }

        public string TableName { get; set; }

        public string ColumnName { get; set; }

        public int RowId { get; set; }

        public string Source { get; set; }

        public string ContentHash { get; set; }

        public string ContentPreview { get; set; }

        public string DetectedDateTime { get; set; }

        public string LastScannedDateTime { get; set; }

        public int MatchingSourceCount { get; set; }

        public string MatchingSourceSortValue { get; set; }

        public bool IsApproved { get; set; }

        public bool? IsPublic { get; set; }

        public string AIReviewDateTime { get; set; }

        public string AIReviewProvider { get; set; }

        public string AIReviewModel { get; set; }

        public bool? AIHasVulnerabilityConcerns { get; set; }

        public string AIRiskAssessment { get; set; }

        public int AIRiskSortOrder { get; set; }

        public string AIReviewDetails { get; set; }

        public string ShortcodeAIRiskAssessment { get; set; }

        public int ShortcodeAIRiskSortOrder { get; set; }

        public List<LavaApprovalEntityDetailBag> EntityDetails { get; set; }

        public static LavaApprovalBag FromContentHash( string contentHash, List<LavaApprovalSource> sources, bool isApproved, Dictionary<string, string> shortcodeRisksByTag = null )
        {
            var firstSource = sources
                .OrderByDescending( s => s.DetectedDateTime )
                .ThenBy( s => s.TableName )
                .ThenBy( s => s.RowId )
                .First();
            var isPublic = sources.Any( s => s.IsPublic == true );
            var riskAssessment = GetDisplayRiskAssessment( firstSource.AIRiskAssessment, isPublic );
            var shortcodeRiskAssessment = GetHighestShortcodeRiskAssessment( sources, shortcodeRisksByTag );

            return new LavaApprovalBag
            {
                IdKey = contentHash,
                TableName = firstSource.TableName,
                ColumnName = firstSource.ColumnName,
                RowId = firstSource.RowId,
                Source = contentHash,
                ContentHash = contentHash,
                ContentPreview = firstSource.ContentPreview,
                DetectedDateTime = FormatDateTime( sources.Max( s => s.DetectedDateTime ) ),
                LastScannedDateTime = FormatDateTime( sources.Max( s => ( DateTime? ) s.LastScannedDateTime ) ),
                MatchingSourceCount = sources.Count,
                MatchingSourceSortValue = sources.Count.ToString( "D10" ),
                IsApproved = isApproved,
                IsPublic = isPublic,
                AIReviewDateTime = FormatDateTime( firstSource.AIReviewDateTime ),
                AIReviewProvider = firstSource.AIReviewProvider,
                AIReviewModel = firstSource.AIReviewModel,
                AIHasVulnerabilityConcerns = firstSource.AIHasVulnerabilityConcerns,
                AIRiskAssessment = riskAssessment,
                AIRiskSortOrder = GetRiskSortOrder( riskAssessment ),
                AIReviewDetails = firstSource.AIReviewDetails,
                ShortcodeAIRiskAssessment = shortcodeRiskAssessment,
                ShortcodeAIRiskSortOrder = GetRiskSortOrder( shortcodeRiskAssessment )
            };
        }

        public static LavaApprovalBag FromEntity( LavaApprovalSource source, int matchingSourceCount, bool isApproved, List<LavaApprovalEntityDetailBag> entityDetails = null, Dictionary<string, string> shortcodeRisksByTag = null )
        {
            var riskAssessment = GetDisplayRiskAssessment( source.AIRiskAssessment, source.IsPublic == true );
            var shortcodeRiskAssessment = GetHighestShortcodeRiskAssessment( new List<LavaApprovalSource> { source }, shortcodeRisksByTag );

            return new LavaApprovalBag
            {
                IdKey = source.IdKey,
                TableName = source.TableName,
                ColumnName = source.ColumnName,
                RowId = source.RowId,
                Source = string.Format( "{0}.{1} #{2}", source.TableName, source.ColumnName, source.RowId ),
                ContentHash = source.ContentHash,
                ContentPreview = source.ContentPreview,
                DetectedDateTime = FormatDateTime( source.DetectedDateTime ),
                LastScannedDateTime = FormatDateTime( source.LastScannedDateTime ),
                MatchingSourceCount = matchingSourceCount,
                MatchingSourceSortValue = matchingSourceCount.ToString( "D10" ),
                IsApproved = isApproved,
                IsPublic = source.IsPublic,
                AIReviewDateTime = FormatDateTime( source.AIReviewDateTime ),
                AIReviewProvider = source.AIReviewProvider,
                AIReviewModel = source.AIReviewModel,
                AIHasVulnerabilityConcerns = source.AIHasVulnerabilityConcerns,
                AIRiskAssessment = riskAssessment,
                AIRiskSortOrder = GetRiskSortOrder( riskAssessment ),
                AIReviewDetails = source.AIReviewDetails,
                ShortcodeAIRiskAssessment = shortcodeRiskAssessment,
                ShortcodeAIRiskSortOrder = GetRiskSortOrder( shortcodeRiskAssessment ),
                EntityDetails = entityDetails ?? new List<LavaApprovalEntityDetailBag>()
            };
        }

        public static int GetRiskSortOrder( string riskAssessment )
        {
            switch ( riskAssessment?.Trim().ToLowerInvariant() )
            {
                case "urgent":
                    return 4;

                case "high":
                    return 3;

                case "medium":
                    return 2;

                case "low":
                    return 1;

                default:
                    return 0;
            }
        }

        private static string FormatDateTime( DateTime? dateTime )
        {
            return dateTime.HasValue ? dateTime.Value.ToString( "g" ) : string.Empty;
        }

        public static string GetDisplayRiskAssessment( string riskAssessment, bool isPublic )
        {
            if ( !isPublic )
            {
                return riskAssessment;
            }

            switch ( riskAssessment?.Trim().ToLowerInvariant() )
            {
                case "high":
                    return "urgent";

                case "medium":
                    return "high";

                case "low":
                    return "medium";

                default:
                    return riskAssessment;
            }
        }

        private static string GetHighestShortcodeRiskAssessment( IEnumerable<LavaApprovalSource> sources, Dictionary<string, string> shortcodeRisksByTag )
        {
            if ( sources == null || shortcodeRisksByTag == null || !shortcodeRisksByTag.Any() )
            {
                return null;
            }

            return sources
                .SelectMany( GetReferencedShortcodeTags )
                .Select( tag => shortcodeRisksByTag.TryGetValue( tag, out var risk ) ? risk : null )
                .Where( risk => risk.IsNotNullOrWhiteSpace() )
                .OrderByDescending( GetRiskSortOrder )
                .FirstOrDefault();
        }

        private static IEnumerable<string> GetReferencedShortcodeTags( LavaApprovalSource source )
        {
            if ( source?.ReferencedShortcodes.IsNullOrWhiteSpace() != false )
            {
                return Enumerable.Empty<string>();
            }

            return source.ReferencedShortcodes.Split( new[] { '|' }, StringSplitOptions.RemoveEmptyEntries );
        }
    }
}
