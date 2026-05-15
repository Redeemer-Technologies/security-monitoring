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

        public string AIReviewDateTime { get; set; }

        public string AIReviewProvider { get; set; }

        public string AIReviewModel { get; set; }

        public bool? AIHasVulnerabilityConcerns { get; set; }

        public string AIRiskAssessment { get; set; }

        public int AIRiskSortOrder { get; set; }

        public string AIReviewDetails { get; set; }

        public List<LavaApprovalEntityDetailBag> EntityDetails { get; set; }

        public static LavaApprovalBag FromContentHash( string contentHash, List<LavaApprovalSource> sources, bool isApproved )
        {
            var firstSource = sources
                .OrderByDescending( s => s.DetectedDateTime )
                .ThenBy( s => s.TableName )
                .ThenBy( s => s.RowId )
                .First();

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
                AIReviewDateTime = FormatDateTime( firstSource.AIReviewDateTime ),
                AIReviewProvider = firstSource.AIReviewProvider,
                AIReviewModel = firstSource.AIReviewModel,
                AIHasVulnerabilityConcerns = firstSource.AIHasVulnerabilityConcerns,
                AIRiskAssessment = firstSource.AIRiskAssessment,
                AIRiskSortOrder = GetRiskSortOrder( firstSource.AIRiskAssessment ),
                AIReviewDetails = firstSource.AIReviewDetails
            };
        }

        public static LavaApprovalBag FromEntity( LavaApprovalSource source, int matchingSourceCount, bool isApproved, List<LavaApprovalEntityDetailBag> entityDetails = null )
        {
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
                AIReviewDateTime = FormatDateTime( source.AIReviewDateTime ),
                AIReviewProvider = source.AIReviewProvider,
                AIReviewModel = source.AIReviewModel,
                AIHasVulnerabilityConcerns = source.AIHasVulnerabilityConcerns,
                AIRiskAssessment = source.AIRiskAssessment,
                AIRiskSortOrder = GetRiskSortOrder( source.AIRiskAssessment ),
                AIReviewDetails = source.AIReviewDetails,
                EntityDetails = entityDetails ?? new List<LavaApprovalEntityDetailBag>()
            };
        }

        public static int GetRiskSortOrder( string riskAssessment )
        {
            switch ( riskAssessment?.Trim().ToLowerInvariant() )
            {
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
    }
}
