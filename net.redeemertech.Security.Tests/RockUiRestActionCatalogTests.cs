using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security.Blocks.Blocks;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class RockUiRestActionCatalogTests
    {
        [TestMethod]
        public void CatalogIdentifiesItsAuditedRockVersion()
        {
            Assert.AreEqual( "17.8", RockUiRestActionCatalog.AuditedRockVersion );
        }

        [DataTestMethod]
        [DataRow( "Rock.Rest.v2.BlockActionsController", "POST", "api/v2/BlockActions/{pageGuid}/{blockGuid}/{actionName}" )]
        [DataRow( "Rock.Rest.v2.CheckInController", "POST", "api/v2/checkin/AttendeeOpportunities" )]
        [DataRow( "Rock.Rest.v2.ControlsController", "POST", "api/v2/Controls/PersonPickerSearch" )]
        [DataRow( "Rock.Rest.v2.UtilitiesController", "GET", "api/v2/Utilities/PersonPreferences/{entityTypeKey}/{entityKey}" )]
        [DataRow( "Rock.Rest.Controllers.CheckinController", "GET", "api/checkin/printsessionlabels" )]
        [DataRow( "Rock.Controllers.SearchController", "GET", "api/search" )]
        [DataRow( "Rock.Rest.Controllers.FileBrowserController", "GET", "api/FileBrowser/GetFileThumbnail" )]
        [DataRow( "Rock.Rest.Controllers.MergeFieldsController", "GET", "api/MergeFields/{mergeFields}" )]
        [DataRow( "Rock.Rest.Controllers.PbxController", "POST", "api/Pbx/Originate" )]
        [DataRow( "Rock.Rest.Controllers.BadgesController", "GET", "api/Badges/FamilyAttendance/{personId}/{monthCount}/{showAsIndividual?}" )]
        public void RockInfrastructureControllersAreNeeded( string controllerClassName, string method, string path )
        {
            Assert.IsTrue( RockUiRestActionCatalog.IsNeededByRock( controllerClassName, method, path ) );
        }

        [DataTestMethod]
        [DataRow( "GET", "api/v2/BlockActions/{pageGuid}/{blockGuid}/{actionName}" )]
        [DataRow( "POST", "/api/v2/checkin/Configuration" )]
        [DataRow( "GET", "api/search" )]
        [DataRow( "GET", "api/Utility/CalculateSlidingDateRange" )]
        [DataRow( "GET", "api/Utility/GetSlidingDateRangeTextValue" )]
        [DataRow( "GET", "api/FileBrowser/GetFileThumbnail" )]
        [DataRow( "GET", "api/MergeFields/GetChildren/{id}" )]
        [DataRow( "POST", "api/Pbx/Originate" )]
        [DataRow( "GET", "api/PersonalLinksController/GetPersonalLinksData" )]
        [DataRow( "GET", "api/Badges/FamilyAttendance/{personId}/{monthCount}/{showAsIndividual?}" )]
        [DataRow( "GET", "api/PersonBadges/{personId}" )]
        [DataRow( "POST", "api/Categories/GetChildren/{id}" )]
        [DataRow( "POST", "api/Categories/GetMetricChildren/{id}" )]
        [DataRow( "POST", "api/Categories/GetDataView/{id}" )]
        [DataRow( "GET", "api/People/Search" )]
        [DataRow( "GET", "api/People/GetSearchDetails" )]
        [DataRow( "GET", "api/People/PopupHtml/{personId}/{emailAsLink}" )]
        [DataRow( "GET", "api/People/VCard/{personGuid}" )]
        [DataRow( "GET", "api/People/GetBlockUserPreference" )]
        [DataRow( "POST", "api/People/SetBlockUserPreference" )]
        [DataRow( "POST", "api/Groups/GetChildren/{id}" )]
        [DataRow( "GET", "api/Groups/GetMapInfo/{groupId}" )]
        [DataRow( "GET", "api/Groups/GetMapInfo/{groupId}/Children" )]
        [DataRow( "GET", "api/Groups/GetMapInfo/{groupId}/Members/{groupMemberStatus?}" )]
        [DataRow( "GET", "api/Groups/GetMapInfo/{groupId}/Families/{statusId}" )]
        [DataRow( "POST", "api/Groups/GetMapInfoWindow/{groupId}/{locationId}" )]
        [DataRow( "POST", "api/Pages/GetChildren/{id}" )]
        [DataRow( "POST", "api/Locations/GetChildren/{id}" )]
        [DataRow( "POST", "api/Locations/GetActiveChildren/{id}" )]
        [DataRow( "GET", "api/FinancialAccounts/GetChildren/{id}" )]
        [DataRow( "GET", "api/FinancialAccounts/GetChildrenBySearchTerm" )]
        [DataRow( "GET", "api/FinancialAccounts/GetParentIds/{id}" )]
        [DataRow( "GET", "api/FinancialAccounts/GetParentIdsCollection" )]
        [DataRow( "POST", "api/WorkflowActionTypes/GetChildren/{id}" )]
        [DataRow( "POST", "api/ConnectionRequests/GetChildren/{id}" )]
        [DataRow( "GET", "api/Tags/AvailableNames" )]
        [DataRow( "GET", "api/MetricValues/GetByMetricId/{metricId}" )]
        [DataRow( "GET", "api/MetricValues/GetSeriesPartitionName/{metricId}" )]
        [DataRow( "GET", "api/AttendanceOccurrences/GetFutureGroupOccurrences" )]
        [DataRow( "POST", "api/AttendanceOccurrences/CreateGroupOccurrence" )]
        [DataRow( "POST", "api/Attendances/GetSchedulerResources" )]
        [DataRow( "POST", "api/Attendances/GetSchedulerResource" )]
        [DataRow( "GET", "api/Attendances/GetAttendingSchedulerResources" )]
        [DataRow( "GET", "api/Attendances/CanSchedulePerson" )]
        [DataRow( "PUT", "api/Attendances/ScheduledPersonAddPending" )]
        [DataRow( "PUT", "api/Attendances/ScheduledPersonAddConfirmed" )]
        [DataRow( "PUT", "api/Attendances/ScheduledPersonConfirm" )]
        [DataRow( "PUT", "api/Attendances/ScheduledPersonDecline" )]
        [DataRow( "PUT", "api/Attendances/ScheduledPersonPending" )]
        [DataRow( "PUT", "api/Attendances/ScheduledPersonRemove" )]
        [DataRow( "PUT", "api/Attendances/ScheduledPersonSendConfirmationCommunication" )]
        [DataRow( "POST", "api/Attendances/RegisterRSVPRecipients" )]
        [DataRow( "POST", "api/MediaElements/WatchInteraction" )]
        [DataRow( "GET", "api/AssetStorageProviders/GetChildren" )]
        [DataRow( "GET", "api/AssetStorageProviders/GetFolders" )]
        [DataRow( "GET", "api/AssetStorageProviders/GetFiles" )]
        [DataRow( "GET", "api/Blocks/{id}" )]
        [DataRow( "PUT", "api/Blocks/Move/{id}" )]
        [DataRow( "DELETE", "api/Blocks/{id}" )]
        [DataRow( "POST", "api/Blocks/Action/{blockGuid}/{actionName}" )]
        [DataRow( "POST", "api/checkin/configuration/status" )]
        [DataRow( "GET", "api/checkin/printsessionlabels" )]
        [DataRow( "POST", "api/ContentChannelItemSlugs/SaveContentSlug/{contentChannelItemId}/{slug}/{contentChannelItemSlugId?}" )]
        [DataRow( "GET", "api/ContentChannelItemSlugs/GetUniqueContentChannelSlug/{contentChannelId}/{slug}" )]
        [DataRow( "DELETE", "api/ContentChannelItemSlugs/{id}" )]
        [DataRow( "GET", "api/GroupMemberHistoricals/GetGroupHistoricalSummary" )]
        [DataRow( "POST", "api/Interactions/RegisterPageInteraction" )]
        [DataRow( "POST", "api/Lava/RenderTemplate" )]
        [DataRow( "GET", "api/Metrics/GetHtmlForBlock/{blockId}" )]
        [DataRow( "GET", "api/ReminderTypes/ReminderTypesExistForEntityType" )]
        [DataRow( "GET", "api/UserLogins/Available" )]
        [DataRow( "GET", "api/ConnectionRequests/ConnectionBoardRequestViewModel/{connectionRequestId}" )]
        [DataRow( "GET", "api/ConnectionRequests/ConnectionBoardStatusViewModels/{connectionOpportunityId}" )]
        [DataRow( "GET", "api/ConnectionRequests/DoesStatusChangeCauseWorkflows/{connectionOpportunityId}/{fromStatusId}/{toStatusId}" )]
        [DataRow( "POST", "api/GroupMembers" )]
        [DataRow( "DELETE", "api/GroupMembers/{id}" )]
        [DataRow( "POST", "api/GroupMembers/GetGroupPlacementGroupMembers" )]
        [DataRow( "GET", "api/RegistrationRegistrants/GetGroupPlacementRegistrants" )]
        [DataRow( "GET", "api/RegistrationTemplatePlacements/CanPlaceRegistrant" )]
        [DataRow( "DELETE", "api/RegistrationTemplatePlacements/DetachPlacementGroup" )]
        [DataRow( "DELETE", "api/ConnectionRequests/{id}" )]
        [DataRow( "DELETE", "api/Groups/{id}" )]
        public void Rock178EndpointIsNeeded( string method, string path )
        {
            Assert.IsTrue( RockUiRestActionCatalog.IsNeededByRock( null, method, path ), method + " " + path );
        }

        [DataTestMethod]
        [DataRow( "POST", "api/Groups/Import" )]
        [DataRow( "POST", "api/ConnectionRequests/{id}" )]
        [DataRow( "GET", "api/Unknown/Action" )]
        [DataRow( "GET", "api/AttendanceOccurrences/Import" )]
        [DataRow( "GET", "api/AttendancesNotRock/GetSchedulerResources" )]
        public void UnrelatedEndpointIsNotNeeded( string method, string path )
        {
            Assert.IsFalse( RockUiRestActionCatalog.IsNeededByRock( null, method, path ), method + " " + path );
        }

        [TestMethod]
        public void PathMatchingIgnoresCaseLeadingSlashTrailingSlashAndQuery()
        {
            Assert.IsTrue( RockUiRestActionCatalog.IsNeededByRock( null, "get", "/API/USERLOGINS/AVAILABLE/?username=test" ) );
        }
    }
}
