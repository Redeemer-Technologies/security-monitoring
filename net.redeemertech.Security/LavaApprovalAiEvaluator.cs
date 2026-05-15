using Rock;
using Rock.Data;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

using net.redeemertech.Security.Model;

namespace net.redeemertech.Security
{
    public class LavaApprovalAiEvaluator
    {
        private const string OpenAIChatCompletionsUrl = "https://api.openai.com/v1/chat/completions";
        private const string DefaultOpenAIModel = "gpt-4o-mini";
        private static readonly HttpClient HttpClient = new HttpClient();

        public LavaApprovalAiEvaluationSummary EvaluateApprovalRequiredContent( RockContext rockContext, string openAIApiKey, string modelName, IEnumerable<string> contentHashes = null )
        {
            if ( openAIApiKey.IsNullOrWhiteSpace() )
            {
                return new LavaApprovalAiEvaluationSummary
                {
                    ErrorMessage = "An OpenAI API key is required."
                };
            }

            modelName = modelName.IsNotNullOrWhiteSpace() ? modelName.Trim() : DefaultOpenAIModel;

            var hashSet = contentHashes == null
                ? null
                : new HashSet<string>( contentHashes.Where( h => h.IsNotNullOrWhiteSpace() ), StringComparer.OrdinalIgnoreCase );

            var sources = new LavaApprovalSourceService( rockContext ).Queryable()
                .Where( s => s.HasApprovalRequiredLava && s.ContentHash != null )
                .ToList();

            if ( hashSet != null )
            {
                sources = sources.Where( s => hashSet.Contains( s.ContentHash ) ).ToList();
            }

            var summary = new LavaApprovalAiEvaluationSummary();

            foreach ( var sourceGroup in sources.GroupBy( s => s.ContentHash, StringComparer.OrdinalIgnoreCase ) )
            {
                var firstCurrentSource = sourceGroup
                    .OrderBy( s => s.TableName )
                    .ThenBy( s => s.ColumnName )
                    .ThenBy( s => s.RowId )
                    .FirstOrDefault( s => string.Equals( ComputeContentHash( GetCurrentSourceContent( rockContext, s ) ), s.ContentHash, StringComparison.OrdinalIgnoreCase ) );

                if ( firstCurrentSource == null )
                {
                    summary.SkippedCount++;
                    continue;
                }

                var content = GetCurrentSourceContent( rockContext, firstCurrentSource );
                if ( content.IsNullOrWhiteSpace() )
                {
                    summary.SkippedCount++;
                    continue;
                }

                try
                {
                    var result = EvaluateContent( openAIApiKey, modelName, content );
                    foreach ( var source in sourceGroup )
                    {
                        source.AIReviewDateTime = RockDateTime.Now;
                        source.AIReviewProvider = "OpenAI";
                        source.AIReviewModel = modelName;
                        source.AIHasVulnerabilityConcerns = result.HasConcerns;
                        source.AIRiskAssessment = result.RiskAssessment;
                        source.AIReviewDetails = result.Details;
                        source.AIReviewRawResponse = result.RawResponse;
                    }

                    rockContext.SaveChanges();
                    summary.EvaluatedCount++;
                }
                catch ( Exception ex )
                {
                    summary.FailedCount++;
                    summary.ErrorMessages.Add( string.Format( "{0}: {1}", sourceGroup.Key, ex.Message ) );
                }
            }

            return summary;
        }

        private LavaApprovalAiEvaluationResult EvaluateContent( string openAIApiKey, string modelName, string content )
        {
            var serializer = new JavaScriptSerializer();
            var payload = new Dictionary<string, object>
            {
                { "model", modelName },
                { "response_format", new Dictionary<string, object> { { "type", "json_object" } } },
                { "messages", new object[]
                {
                    new Dictionary<string, object>
                    {
                        { "role", "system" },
                        { "content", BuildSystemPrompt() }
                    },
                    new Dictionary<string, object>
                    {
                        { "role", "user" },
                        { "content", "Evaluate this Lava/Liquid content:\n\n```liquid\n" + content + "\n```" }
                    }
                } }
            };

            var request = new HttpRequestMessage( HttpMethod.Post, OpenAIChatCompletionsUrl );
            request.Headers.Authorization = new AuthenticationHeaderValue( "Bearer", openAIApiKey );
            request.Content = new StringContent( serializer.Serialize( payload ), Encoding.UTF8, "application/json" );

            var response = Task.Run( () => HttpClient.SendAsync( request ) ).Result;
            var responseBody = Task.Run( () => response.Content.ReadAsStringAsync() ).Result;

            if ( !response.IsSuccessStatusCode )
            {
                throw new Exception( string.Format( "OpenAI returned HTTP {0}: {1}", ( int ) response.StatusCode, ExtractOpenAIErrorMessage( responseBody ) ) );
            }

            var rawResponse = ExtractOpenAIMessageContent( responseBody );
            var parsed = ParseResult( rawResponse );
            parsed.RawResponse = rawResponse;

            return parsed;
        }

        private string ExtractOpenAIMessageContent( string responseBody )
        {
            try
            {
                var serializer = new JavaScriptSerializer();
                var response = serializer.Deserialize<Dictionary<string, object>>( responseBody );
                var choices = ToObjectEnumerable( response.GetValueOrNull( "choices" ) );
                var firstChoice = choices.OfType<Dictionary<string, object>>().FirstOrDefault();
                var message = firstChoice?.GetValueOrNull( "message" ) as Dictionary<string, object>;

                return message?.GetValueOrNull( "content" ).ToStringSafe() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private IEnumerable<object> ToObjectEnumerable( object value )
        {
            var objectArray = value as object[];
            if ( objectArray != null )
            {
                return objectArray;
            }

            var arrayList = value as ArrayList;
            if ( arrayList != null )
            {
                return arrayList.Cast<object>();
            }

            return Enumerable.Empty<object>();
        }

        private string ExtractOpenAIErrorMessage( string responseBody )
        {
            try
            {
                var serializer = new JavaScriptSerializer();
                var response = serializer.Deserialize<Dictionary<string, object>>( responseBody );
                var error = response.GetValueOrNull( "error" ) as Dictionary<string, object>;
                var message = error?.GetValueOrNull( "message" ).ToStringSafe();

                return message.IsNotNullOrWhiteSpace() ? message : responseBody;
            }
            catch
            {
                return responseBody;
            }
        }

        private string BuildSystemPrompt()
        {
            return @"You are reviewing Rock RMS Lava/Liquid template content for cross-site scripting (XSS) and SQL injection risk.
Return only a JSON object with these properties:
{
  ""hasConcerns"": true|false,
  ""riskAssessment"": ""low""|""medium""|""high"",
  ""details"": ""short explanation of the judgement""
}

Focus on whether this template could allow untrusted input to execute script, inject HTML/JavaScript, or alter SQL/database queries.
In Rock Lava, {% sql %}{% endsql %} tags allow SQL to run in the template. Liquid/Lava tags or variables that appear inside SQL must be sanitized or parameterized to be safe.
Tags such as {% person %}, or other tags that start with {% %} and then a Rock entity name, are entity tags and can query the database. Expressions or where clauses on those entity tags generally need an explicit permission check
to ensure the current user has permissions to access the data that is returned.
Treat direct script output, unsafe HTML rendering, unsanitized request/query/form values, dynamic SQL, and entity queries without permissions checks as concerns.";
        }

        private LavaApprovalAiEvaluationResult ParseResult( string rawResponse )
        {
            var json = ExtractJsonObject( rawResponse );
            if ( json.IsNullOrWhiteSpace() )
            {
                return new LavaApprovalAiEvaluationResult
                {
                    HasConcerns = null,
                    RiskAssessment = "medium",
                    Details = "OpenAI did not return parseable JSON. Review the raw response."
                };
            }

            try
            {
                var serializer = new JavaScriptSerializer();
                var values = serializer.Deserialize<Dictionary<string, object>>( json );
                var riskAssessment = GetDictionaryValue( values, "riskAssessment" ).ToStringSafe().ToLowerInvariant();

                if ( riskAssessment != "low" && riskAssessment != "medium" && riskAssessment != "high" )
                {
                    riskAssessment = "medium";
                }

                return new LavaApprovalAiEvaluationResult
                {
                    HasConcerns = GetDictionaryValue( values, "hasConcerns" ).ToStringSafe().AsBooleanOrNull(),
                    RiskAssessment = riskAssessment,
                    Details = GetDictionaryValue( values, "details" ).ToStringSafe()
                };
            }
            catch
            {
                return new LavaApprovalAiEvaluationResult
                {
                    HasConcerns = null,
                    RiskAssessment = "medium",
                    Details = "OpenAI returned invalid JSON. Review the raw response."
                };
            }
        }

        private object GetDictionaryValue( Dictionary<string, object> values, string key )
        {
            return values.FirstOrDefault( v => string.Equals( v.Key, key, StringComparison.OrdinalIgnoreCase ) ).Value;
        }

        private string ExtractJsonObject( string response )
        {
            if ( response.IsNullOrWhiteSpace() )
            {
                return string.Empty;
            }

            var firstBrace = response.IndexOf( '{' );
            var lastBrace = response.LastIndexOf( '}' );
            if ( firstBrace < 0 || lastBrace <= firstBrace )
            {
                return string.Empty;
            }

            return response.Substring( firstBrace, lastBrace - firstBrace + 1 );
        }

        private string GetCurrentSourceContent( RockContext rockContext, LavaApprovalSource source )
        {
            var target = GetAllowedSourceTarget( source.TableName, source.ColumnName );
            if ( target == null )
            {
                return null;
            }

            return rockContext.Database.SqlQuery<string>(
                string.Format( "SELECT [{0}] FROM [dbo].[{1}] WHERE [Id] = @RowId", target.ColumnName, target.TableName ),
                new SqlParameter( "@RowId", source.RowId ) ).FirstOrDefault();
        }

        private LavaSourceTarget GetAllowedSourceTarget( string tableName, string columnName )
        {
            return GetAllowedSourceTargets()
                .FirstOrDefault( t => t.TableName.Equals( tableName, StringComparison.OrdinalIgnoreCase ) && t.ColumnName.Equals( columnName, StringComparison.OrdinalIgnoreCase ) );
        }

        private List<LavaSourceTarget> GetAllowedSourceTargets()
        {
            return new List<LavaSourceTarget>
            {
                new LavaSourceTarget( "AttributeValue", "Value" ),
                new LavaSourceTarget( "HtmlContent", "Content" ),
                new LavaSourceTarget( "Block", "PreHtml" ),
                new LavaSourceTarget( "Block", "PostHtml" ),
                new LavaSourceTarget( "LavaShortcode", "Markup" ),
                new LavaSourceTarget( "ContentChannelItem", "Content" )
            };
        }

        private string ComputeContentHash( string content )
        {
            using ( var sha256 = SHA256.Create() )
            {
                var hashBytes = sha256.ComputeHash( Encoding.UTF8.GetBytes( content ?? string.Empty ) );
                return string.Concat( hashBytes.Select( b => b.ToString( "x2" ) ) );
            }
        }

        private class LavaApprovalAiEvaluationResult
        {
            public bool? HasConcerns { get; set; }

            public string RiskAssessment { get; set; }

            public string Details { get; set; }

            public string RawResponse { get; set; }
        }

        private class LavaSourceTarget
        {
            public LavaSourceTarget( string tableName, string columnName )
            {
                TableName = tableName;
                ColumnName = columnName;
            }

            public string TableName { get; private set; }

            public string ColumnName { get; private set; }
        }
    }

    public class LavaApprovalAiEvaluationSummary
    {
        public int EvaluatedCount { get; set; }

        public int SkippedCount { get; set; }

        public int FailedCount { get; set; }

        public string ErrorMessage { get; set; }

        public List<string> ErrorMessages { get; set; } = new List<string>();

        public bool HasError
        {
            get
            {
                return ErrorMessage.IsNotNullOrWhiteSpace();
            }
        }
    }
}
