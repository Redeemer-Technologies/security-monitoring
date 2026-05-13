using net.redeemertech.Security.Model;
using System;
using System.Collections.Generic;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class IISAlertHistoryBag
    {
        public string IdKey { get; set; }
        public string IISAlertIdKey { get; set; }
        public string AlertName { get; set; }
        public string TrippedDateTime { get; set; }
        public int ResultCount { get; set; }
        public string Summary { get; set; }
        public string ResultJson { get; set; }

        public string ErrorMessage { get; set; }

        public static IISAlertHistoryBag FromEntity(IISAlertHistory history)
        {
            return new IISAlertHistoryBag
            {
                IdKey = history.IdKey,
                IISAlertIdKey = history.IISAlert?.IdKey,
                AlertName = history.AlertName,
                TrippedDateTime = history.TrippedDateTime.ToString("g"),
                ResultCount = history.ResultCount,
                Summary = history.Summary,
                ResultJson = history.ResultJson
            };
        }
    }
}
