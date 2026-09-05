using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Blocks;
using Rock.Model;
using Rock.ViewModels.Utility;
using Rock.Web.Cache;

using System.ComponentModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Script.Serialization;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "IIS Alert Detail" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Edits a single IIS alert." )]
    [SupportedSiteTypes( Rock.Model.SiteType.Web )]
    [Rock.SystemGuid.EntityTypeGuid("2069f66c-9dac-4250-a694-521e463adb4a")]
    [Rock.SystemGuid.BlockTypeGuid("c8032b08-fc23-479d-90d3-9ddf049a6a3c")]
    public class IISAlertDetail : RockBlockType
    {
        private const string DefaultQuery = "SELECT *\nFROM [[logs]]\nLIMIT 100";
        private const string DefaultSummaryLava = "IIS alert returned {{ results | Size }} row(s).";
        private const string DefaultRealtimeSummaryLava = "Request denied from IP {{ Request.ClientIp }}";
        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/iisAlertDetail.obs";

        public override object GetObsidianBlockInitialization()
        {
            var alert = GetAlert();

            if (alert == null)
            {
                return new IISAlertsInitializationBox { ErrorMessage = "IIS alert was not found." };
            }
            if (!alert.IsAuthorized(Rock.Security.Authorization.VIEW, RequestContext.CurrentPerson))
            {
                return new IISAlertsInitializationBox { ErrorMessage = "Not authorized to view IIS alerts." };
            }

            return new IISAlertsInitializationBox
            {
                IsEditable = alert.IsAuthorized(Rock.Security.Authorization.EDIT, RequestContext.CurrentPerson),
                Alert = IISAlertBag.FromEntity(alert),
                DefaultDateRange = IISLogDuckDbQuery.ToSlidingDateRangeBag(IISLogDuckDbQuery.DefaultDateRange),
                SecurityRoles = GetSecurityRoles()
            };
        }

        [BlockAction]
        public BlockActionResult SaveAlert(IISAlertBag bag)
        {
            var service = new IISAlertService(RockContext);
            var alert = bag.IdKey.IsNullOrWhiteSpace() ? new IISAlert() : service.Get(bag.IdKey, !PageCache.Layout.Site.DisablePredictableIds);
            if (alert == null)
            {
                return ActionNotFound("IIS alert was not found.");
            }

            if (!alert.IsAuthorized(Rock.Security.Authorization.EDIT, RequestContext.CurrentPerson))
            {
                return ActionForbidden("Not authorized to edit IIS alerts.");
            }

            IISAlertEvaluationMode evaluationMode;
            IISRequestRuleStage requestStage;
            IISRequestRuleConditionLogic conditionLogic;
            if ( !Enum.TryParse( bag.EvaluationMode.IfEmpty( IISAlertEvaluationMode.LogQuery.ToString() ), true, out evaluationMode )
                || !Enum.TryParse( bag.RequestStage.IfEmpty( IISRequestRuleStage.PreAuthentication.ToString() ), true, out requestStage )
                || !Enum.TryParse( bag.ConditionLogic.IfEmpty( IISRequestRuleConditionLogic.All.ToString() ), true, out conditionLogic )
                || !Enum.IsDefined( typeof( IISAlertEvaluationMode ), evaluationMode )
                || !Enum.IsDefined( typeof( IISRequestRuleStage ), requestStage )
                || !Enum.IsDefined( typeof( IISRequestRuleConditionLogic ), conditionLogic ) )
            {
                return ActionBadRequest( "The rule type, processing stage, or condition logic is invalid." );
            }

            var conditions = ( bag.Conditions ?? new List<IISAlertConditionBag>() ).Select( condition => condition?.ToEntity() ).ToList();

            alert.Name = bag.Name?.Trim();
            alert.Description = bag.Description;
            alert.IsActive = bag.IsActive;
            alert.EvaluationMode = evaluationMode;
            alert.RequestStage = requestStage;
            alert.ConditionLogic = conditionLogic;
            alert.ConditionsJson = new JavaScriptSerializer().Serialize( conditions );
            alert.Query = bag.Query.IfEmpty( evaluationMode == IISAlertEvaluationMode.LogQuery ? null : string.Empty );
            alert.SummaryLava = bag.SummaryLava.IfEmpty(
                evaluationMode == IISAlertEvaluationMode.RealTimeRule ? DefaultRealtimeSummaryLava : DefaultSummaryLava );
            alert.DateRange = IISLogDuckDbQuery.ToDelimitedDateRange(bag.DateRange).IfEmpty(IISLogDuckDbQuery.DefaultDateRange);
            alert.NotificationEmails = bag.NotificationEmails;
            alert.EvaluationFrequencyMinutes = bag.EvaluationFrequencyMinutes < 1 ? 1 : bag.EvaluationFrequencyMinutes;
            alert.BlockIpAddress = bag.BlockIpAddress;
            alert.BlockIpAddressMinutes = bag.BlockIpAddress ? System.Math.Max( 1, bag.BlockIpAddressMinutes ?? 60 ) : ( int? ) null;
            alert.LockOutUserAccounts = bag.LockOutUserAccounts;
            alert.BlockRequest = evaluationMode == IISAlertEvaluationMode.RealTimeRule && requestStage != IISRequestRuleStage.EndRequest && bag.BlockRequest;
            alert.BlockResponseStatusCode = alert.BlockRequest ? bag.BlockResponseStatusCode ?? 403 : ( int? ) null;
            alert.BlockResponseMessage = alert.BlockRequest ? bag.BlockResponseMessage : null;

            if ( alert.Name.IsNullOrWhiteSpace() )
            {
                return ActionBadRequest( "Name is required." );
            }

            if ( evaluationMode == IISAlertEvaluationMode.LogQuery && alert.Query.IsNullOrWhiteSpace() )
            {
                return ActionBadRequest( "A SQL query is required for historical log alerts." );
            }

            if ( evaluationMode == IISAlertEvaluationMode.RealTimeRule )
            {
                List<IISRequestRuleConditionMatcher> conditionMatchers;
                List<string> validationErrors;
                if ( !IISRequestRuleCompiler.TryCompile( requestStage, conditionLogic, conditions, out conditionMatchers, out validationErrors ) )
                {
                    return ActionBadRequest( string.Join( " ", validationErrors ) );
                }

                foreach ( var condition in conditions.Where( condition => condition != null ) )
                {
                    if ( string.Equals( condition.Field, IISRequestRuleField.SecurityRole, StringComparison.OrdinalIgnoreCase )
                        && RoleCache.Get( condition.Value.AsGuid() ) == null )
                    {
                        return ActionBadRequest( "The selected security role does not exist or is inactive." );
                    }
                }

                if ( alert.BlockRequest && ( alert.BlockResponseStatusCode < 400 || alert.BlockResponseStatusCode > 599 ) )
                {
                    return ActionBadRequest( "The blocked-request response code must be between 400 and 599." );
                }

                if ( requestStage == IISRequestRuleStage.PreAuthentication )
                {
                    alert.LockOutUserAccounts = false;
                }
            }

            if (alert.Id == 0)
            {
                service.Add(alert);
            }

            RockContext.SaveChanges();
            IISAlertRuleCache.Reload();
            return ActionOk( IISAlertBag.FromEntity( alert ) );
        }

        private IISAlert GetNewAlert()
        {
            return new IISAlert {
                IsActive = true,
                Query = DefaultQuery,
                SummaryLava = DefaultSummaryLava,
                DateRange = IISLogDuckDbQuery.DefaultDateRange,
                EvaluationFrequencyMinutes = 60,
                BlockIpAddressMinutes = 60,
                EvaluationMode = IISAlertEvaluationMode.LogQuery,
                RequestStage = IISRequestRuleStage.PreAuthentication,
                ConditionLogic = IISRequestRuleConditionLogic.All,
                ConditionsJson = "[]",
                BlockResponseStatusCode = 403
            };
        }

        private IISAlert GetAlert()
        {
            var idKey = PageParameter( "IISAlertId" );
            return idKey.IsNullOrWhiteSpace() || idKey == "0" ? GetNewAlert() : new IISAlertService( RockContext ).Get( idKey, !PageCache.Layout.Site.DisablePredictableIds );
        }

        private List<ListItemBag> GetSecurityRoles()
        {
            var securityRoleGroupTypeId = GroupTypeCache.GetSecurityRoleGroupType()?.Id ?? 0;
            return new GroupService( RockContext ).Queryable()
                .Where( group => group.IsActive && ( group.IsSecurityRole || group.GroupTypeId == securityRoleGroupTypeId ) )
                .OrderBy( group => group.Name )
                .Select( group => new
                {
                    group.Name,
                    group.Guid
                } )
                .ToList()
                .Select( group => new ListItemBag
                {
                    Text = group.Name,
                    Value = group.Guid.ToString()
                } )
                .ToList();
        }
    }
}
