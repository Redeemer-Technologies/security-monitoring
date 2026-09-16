using System;
using System.Collections.Generic;
using System.Linq;

namespace net.redeemertech.Security.Blocks.Blocks
{
    /// <summary>
    /// REST actions that Rock UI controls (WebForms and Obsidian) call at runtime.
    /// Generated entity CRUD is excluded except where a control still posts to it.
    /// </summary>
    internal static class RockUiRestActionCatalog
    {
        /// <summary>
        /// The Rock release whose core WebForms and Obsidian sources were used to
        /// build this catalog. Re-audit the catalog whenever this version changes.
        /// </summary>
        internal const string AuditedRockVersion = "17.8";

        // These controllers exist specifically to serve Rock's own UI/runtime. All
        // actions on them are considered required, including actions added by a
        // Rock 17.8 patch release without a distinct URL entry below.
        private static readonly HashSet<string> ControllerClassNames = new HashSet<string>( StringComparer.OrdinalIgnoreCase )
        {
            "Rock.Rest.v2.BlockActionsController",
            "Rock.Rest.v2.CheckInController",
            "Rock.Rest.v2.ControlsController",
            "Rock.Rest.v2.UtilitiesController",
            "Rock.Controllers.SearchController",
            "Rock.Rest.Controllers.CheckinController",
            "Rock.Rest.Controllers.FileBrowserController",
            "Rock.Rest.Controllers.MergeFieldsController",
            "Rock.Rest.Controllers.PbxController"
        };

        /// <summary>
        /// Action-route prefixes (no leading slash, lower-case) that identify UI-used
        /// custom endpoints. A path matches when it equals the prefix or continues with
        /// '/' (route parameters). Do not list an entity controller root here; that
        /// would also mark generated CRUD such as SetContext.
        /// </summary>
        private static readonly string[] PathPrefixes = new[]
        {
            // Obsidian infrastructure.
            "api/v2/blockactions",
            "api/v2/controls",
            "api/v2/checkin",
            "api/v2/utilities",

            // Shared WebForms controls.
            "api/utility/calculateslidingdaterange",
            "api/utility/getslidingdaterangetextvalue",
            "api/filebrowser/getfilethumbnail",
            "api/mergefields/getchildren",
            "api/pbx/originate",
            "api/personallinkscontroller/getpersonallinksdata",
            "api/personallinks/getpersonallinksdata",
            "api/badges/ingroupoftype",
            "api/badges/ingroupwithpurpose",
            "api/badges/geofencinggroups",
            "api/badges/weeksattendedinduration",
            "api/badges/lastvisitonsite",
            "api/badges/personaldevicesnumber",
            "api/badges/familyattendance",
            "api/badges/interactionsinrange",
            "api/personbadges/ingroupoftype",
            "api/personbadges/ingroupwithpurpose",
            "api/personbadges/geofencinggroups",
            "api/personbadges/weeksattendedinduration",
            "api/personbadges/lastvisitonsite",
            "api/personbadges/personaldevicesnumber",
            "api/personbadges/familyattendance",
            "api/personbadges/interactionsinrange",
            "api/categories/getchildren",
            "api/categories/getmetricchildren",
            "api/categories/getdataview",
            "api/people/search",
            "api/people/getsearchdetails",
            "api/people/popuphtml",
            "api/people/vcard",
            "api/people/getblockuserpreference",
            "api/people/setblockuserpreference",
            "api/groups/getchildren",
            "api/groups/getmapinfo",
            "api/groups/getmapinfowindow",
            "api/pages/getchildren",
            "api/locations/getchildren",
            "api/locations/getactivechildren",
            "api/financialaccounts/getchildren",
            "api/financialaccounts/getchildrenbysearchterm",
            "api/financialaccounts/getparentids",
            "api/financialaccounts/getparentidscollection",
            "api/workflowactiontypes/getchildren",
            "api/connectionrequests/getchildren",
            "api/tags/availablenames",
            "api/metricvalues/getbymetricid",
            "api/metricvalues/getseriespartitionname",
            "api/attendanceoccurrences/getfuturegroupoccurrences",
            "api/attendanceoccurrences/creategroupoccurrence",
            "api/attendances/getschedulerresources",
            "api/attendances/getschedulerresource",
            "api/attendances/getattendingschedulerresources",
            "api/attendances/canscheduleperson",
            "api/attendances/scheduledpersonaddpending",
            "api/attendances/scheduledpersonaddconfirmed",
            "api/attendances/scheduledpersonconfirm",
            "api/attendances/scheduledpersondecline",
            "api/attendances/scheduledpersonpending",
            "api/attendances/scheduledpersonremove",
            "api/attendances/scheduledpersonsendconfirmationcommunication",
            "api/attendances/registerrsvprecipients",
            "api/mediaelements/watchinteraction",
            "api/assetstorageproviders/getchildren",
            "api/assetstorageproviders/getfolders",
            "api/assetstorageproviders/getfiles",

            // Core pages and administrative controls.
            "api/blocks/move",
            "api/blocks/action",
            "api/checkin/configuration",
            "api/checkin/printsessionlabels",
            "api/contentchannelitemslugs/savecontentslug",
            "api/contentchannelitemslugs/getuniquecontentchannelslug",
            "api/groupmemberhistoricals/getgrouphistoricalsummary",
            "api/interactions/registerpageinteraction",
            "api/lava/rendertemplate",
            "api/metrics/gethtmlforblock",
            "api/remindertypes/remindertypesexistforentitytype",
            "api/userlogins/available",

            // Group placement and connection board controls.
            "api/connectionrequests/connectionboardrequestviewmodel",
            "api/connectionrequests/connectionboardstatusviewmodels",
            "api/connectionrequests/doesstatuschangecauseworkflows",
            "api/groupmembers/getgroupplacementgroupmembers",
            "api/registrationregistrants/getgroupplacementregistrants",
            "api/registrationtemplateplacements/canplaceregistrant",
            "api/registrationtemplateplacements/detachplacementgroup"
        };

        // Rock's UI calls these generated CRUD endpoints directly. Match the
        // RestAction path template exactly so sibling actions on the same
        // controller (SetContext, OData GET, generic PUT/PATCH) stay excluded.
        private static readonly Dictionary<string, string[]> MethodExactPaths = new Dictionary<string, string[]>( StringComparer.OrdinalIgnoreCase )
        {
            { "GET", new[] { "api/blocks/{id}", "api/search", "api/mergefields/{id}" } },
            { "POST", new[] { "api/groupmembers", "api/followings" } },
            { "DELETE", new[]
                {
                    "api/blocks/{id}",
                    "api/contentchannelitemslugs/{id}",
                    "api/groupmembers/{id}",
                    "api/connectionrequests/{id}",
                    "api/groups/{id}"
                }
            }
        };

        public static bool IsNeededByRock( string controllerClassName, string method, string path )
        {
            if ( !string.IsNullOrWhiteSpace( controllerClassName ) && ControllerClassNames.Contains( controllerClassName.Trim() ) )
            {
                return true;
            }

            var normalized = NormalizePath( path );
            if ( normalized.Length == 0 )
            {
                return false;
            }

            var pathWithoutQuery = StripQuery( normalized );
            var methodName = ( method ?? string.Empty ).Trim().ToUpperInvariant();

            foreach ( var prefix in PathPrefixes )
            {
                if ( PathEqualsOrIsChild( pathWithoutQuery, prefix ) )
                {
                    return true;
                }
            }

            if ( MethodExactPaths.TryGetValue( methodName, out var exactPaths )
                && exactPaths.Any( exactPath => pathWithoutQuery == exactPath ) )
            {
                return true;
            }

            // TagList uses custom Tags/TaggedItems overloads identified by entityTypeId query params.
            if ( pathWithoutQuery == "api/tags" && normalized.IndexOf( "entitytypeid", StringComparison.OrdinalIgnoreCase ) >= 0 )
            {
                return true;
            }

            if ( pathWithoutQuery == "api/taggeditems" && normalized.IndexOf( "entitytypeid", StringComparison.OrdinalIgnoreCase ) >= 0 )
            {
                return true;
            }

            // Followings toggler: custom DELETE with entity type + entity keys.
            // Generated DELETE api/Followings/{id} is a single extra segment and is not used.
            if ( methodName == "DELETE"
                && pathWithoutQuery.StartsWith( "api/followings/", StringComparison.Ordinal )
                && pathWithoutQuery.Count( c => c == '/' ) >= 3 )
            {
                return true;
            }

            return false;
        }

        private static bool PathEqualsOrIsChild( string pathWithoutQuery, string prefix )
        {
            return pathWithoutQuery == prefix || pathWithoutQuery.StartsWith( prefix + "/", StringComparison.Ordinal );
        }

        private static string NormalizePath( string path )
        {
            if ( string.IsNullOrWhiteSpace( path ) )
            {
                return string.Empty;
            }

            return path.Trim().TrimStart( '/' ).ToLowerInvariant();
        }

        private static string StripQuery( string normalizedPath )
        {
            var queryIndex = normalizedPath.IndexOf( '?' );
            var withoutQuery = queryIndex >= 0 ? normalizedPath.Substring( 0, queryIndex ) : normalizedPath;
            return withoutQuery.TrimEnd( '/' );
        }
    }
}
