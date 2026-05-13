using net.redeemertech.Security.Model;

using Rock;
using Rock.Attribute;
using Rock.Communication;
using Rock.Data;
using Rock.Jobs;
using Rock.Model;

using Quartz;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace net.redeemertech.Security
{
    [DisplayName( "Process IIS Alerts" )]
    [Description( "Evaluates active IIS alerts against processed IIS log parquet files and emails configured recipients when an alert trips." )]
    [TextField( "Parquet Folder", "The folder containing parquet files created by Process IIS Logs. Relative paths are resolved under App_Data.", true, "IISLogParquet", key: AttributeKey.ParquetFolder, order: 0 )]
    [IntegerField( "Maximum Parquet Files", "The maximum number of parquet files to include in each alert query.", false, 1000, key: AttributeKey.MaximumParquetFiles, order: 1 )]
    [IntegerField( "Query Timeout Seconds", "The amount of time in seconds to allow each alert query to run before timing out.", false, 10, key: AttributeKey.QueryTimeoutSeconds, order: 2 )]
    [SystemCommunicationField( "Alert Email", "The system communication used to notify recipients when an IIS alert trips.", true, key: AttributeKey.AlertEmail, order: 3 )]
    [LinkedPage( "Alert History Detail Page", "The page that displays a single tripped alert history record.", false, key: AttributeKey.AlertHistoryDetailPage, order: 4 )]
    [DisallowConcurrentExecution]
    public class ProcessIISAlerts : RockJob
    {
        private static class AttributeKey
        {
            public const string ParquetFolder = "ParquetFolder";
            public const string MaximumParquetFiles = "MaximumParquetFiles";
            public const string QueryTimeoutSeconds = "QueryTimeoutSeconds";
            public const string AlertEmail = "AlertEmail";
            public const string AlertHistoryDetailPage = "AlertHistoryDetailPage";
        }

        public override void Execute()
        {
            using (var rockContext = new RockContext())
            {
                var alertService = new IISAlertService(rockContext);
                var historyService = new IISAlertHistoryService(rockContext);
                var now = RockDateTime.Now;
                var alerts = alertService.Queryable()
                    .Where(a => a.IsActive)
                    .OrderBy(a => a.Name)
                    .ToList();

                var evaluatedCount = 0;
                var trippedCount = 0;
                var errors = new List<string>();

                var defaultParquetFolder = GetAttributeValue(AttributeKey.ParquetFolder);
                var defaultMaximumParquetFiles = GetAttributeValue(AttributeKey.MaximumParquetFiles).AsIntegerOrNull() ?? 1000;
                var defaultQueryTimeoutSeconds = GetAttributeValue(AttributeKey.QueryTimeoutSeconds).AsIntegerOrNull() ?? 10;

                foreach (var alert in alerts)
                {
                    if (!ShouldEvaluate(alert, now))
                    {
                        continue;
                    }

                    evaluatedCount++;
                    try
                    {
                        var resultTable = new IISLogDuckDbQuery().Execute(
                            alert.Query,
                            alert.DateRange,
                            defaultParquetFolder,
                            defaultMaximumParquetFiles,
                            defaultQueryTimeoutSeconds
                        );

                        alert.LastRunDateTime = now;

                        if (resultTable.Rows.Count > 0)
                        {
                            var history = new IISAlertHistory
                            {
                                IISAlertId = alert.Id,
                                AlertName = alert.Name,
                                TrippedDateTime = now,
                                ResultCount = resultTable.Rows.Count,
                                ResultJson = SerializeResults(resultTable)
                            };

                            historyService.Add(history);
                            rockContext.SaveChanges();
                            trippedCount++;
                            SendAlertEmail(alert, history);
                        }
                        else
                        {
                            rockContext.SaveChanges();
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Add(string.Format("{0}: {1}", alert.Name, ex.Message));
                    }
                }

                this.Result = string.Format("Evaluated {0:N0} IIS alerts; {1:N0} tripped.", evaluatedCount, trippedCount);
                if (errors.Any())
                {
                    var message = " Errors: " + errors.JoinStrings("; ");
                    this.Result += message;
                    throw new Exception(message);
                }
            }
        }

        private static bool ShouldEvaluate( IISAlert alert, DateTime now )
        {
            var frequencyMinutes = Math.Max( 1, alert.EvaluationFrequencyMinutes );
            return !alert.LastRunDateTime.HasValue || alert.LastRunDateTime.Value.AddMinutes( frequencyMinutes ) <= now;
        }

        private void SendAlertEmail( IISAlert alert, IISAlertHistory history )
        {
            var systemCommunicationGuid = GetAttributeValue( AttributeKey.AlertEmail ).AsGuidOrNull();
            var recipientEmails = alert.NotificationEmails.SplitDelimitedValues().Where( e => e.IsNotNullOrWhiteSpace() ).Distinct().ToList();
            if ( !systemCommunicationGuid.HasValue || !recipientEmails.Any() )
            {
                return;
            }

            var mergeFields = Rock.Lava.LavaHelper.GetCommonMergeFields( null );
            mergeFields.AddOrReplace( "AlertName", alert.Name );
            mergeFields.AddOrReplace( "AlertHistoryUrl", GetAlertHistoryUrl( history.Id ) );

            var emailMessage = new RockEmailMessage( systemCommunicationGuid.Value );
            foreach ( var email in recipientEmails )
            {
                emailMessage.AddRecipient( RockEmailMessageRecipient.CreateAnonymous( email, mergeFields ) );
            }

            var errors = new List<string>();
            emailMessage.Send( out errors );
            if ( errors.Any() )
            {
                throw new Exception( errors.JoinStrings( "; " ) );
            }
        }

        private string GetAlertHistoryUrl( int historyId )
        {
            var pageValue = GetAttributeValue( AttributeKey.AlertHistoryDetailPage );
            if ( pageValue.IsNullOrWhiteSpace() )
            {
                return string.Empty;
            }

            var pageReference = new Rock.Web.PageReference( pageValue, new Dictionary<string, string> { { "IISAlertHistoryId", historyId.ToString() } } );
            return pageReference.PageId > 0 ? pageReference.BuildUrl() : string.Empty;
        }

        private static string SerializeResults( DataTable table )
        {
            var rows = new List<Dictionary<string, object>>();
            foreach ( DataRow row in table.Rows )
            {
                var values = new Dictionary<string, object>();
                foreach ( DataColumn column in table.Columns )
                {
                    var value = row[column];
                    values[column.ColumnName] = value == DBNull.Value ? null : value;
                }

                rows.Add( values );
            }

            return new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize( rows );
        }
    }
}
