using net.redeemertech.Security.Model;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class IISAlertConditionBag
    {
        public string Field { get; set; }

        public string Operator { get; set; }

        public string Value { get; set; }

        public string HeaderName { get; set; }

        public bool IgnoreCase { get; set; }

        public IISRequestRuleCondition ToEntity()
        {
            return new IISRequestRuleCondition
            {
                Field = Field,
                Operator = Operator,
                Value = Value,
                HeaderName = HeaderName,
                IgnoreCase = IgnoreCase
            };
        }

        public static IISAlertConditionBag FromEntity( IISRequestRuleCondition condition )
        {
            return new IISAlertConditionBag
            {
                Field = condition.Field,
                Operator = condition.Operator,
                Value = condition.Value,
                HeaderName = condition.HeaderName,
                IgnoreCase = condition.IgnoreCase
            };
        }
    }
}
