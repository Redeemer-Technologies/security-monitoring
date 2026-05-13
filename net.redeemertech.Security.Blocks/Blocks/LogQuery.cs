using net.redeemertech.Security;
using net.redeemertech.Security.Blocks.ViewModels;

using Rock;
using Rock.Attribute;
using Rock.Blocks;
using Rock.Data;
using Rock.Enums.Controls;
using Rock.Field.Types;
using Rock.Lava;
using Rock.Model;
using Rock.Obsidian.UI;
using Rock.ViewModels.Blocks;
using Rock.ViewModels.Blocks.Reporting.DynamicData;
using Rock.ViewModels.Cms;
using Rock.ViewModels.Controls;
using Rock.ViewModels.Core.Grid;
using Rock.ViewModels.Utility;
using Rock.Web.Cache;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Linq;
using System.Text.RegularExpressions;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "IIS Log Query" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Queries IIS log parquet files created by the Process IIS Logs job using DuckDB." )]
    [SupportedSiteTypes( SiteType.Web )]

    [TextField( "Parquet Folder",
        "The folder containing parquet files created by Process IIS Logs. Relative paths are resolved under App_Data.",
        true,
        "IISLogParquet",
        key: AttributeKey.ParquetFolder,
        order: 0 )]
    [IntegerField( "Maximum Parquet Files",
        "The maximum number of parquet files to include in a query. Use this as a safeguard if the log folder grows unexpectedly.",
        false,
        1000,
        key: AttributeKey.MaximumParquetFiles,
        order: 1 )]
    [LavaCommandsField( "Enabled Lava Commands",
        Key = AttributeKey.EnabledLavaCommands,
        Description = "The Lava commands that should be enabled when resolving the SQL query and Lava output template.",
        Order = 2,
        IsRequired = false )]

    [TextField( "SQL Query",
        Key = AttributeKey.Query,
        Description = "The DuckDB SQL query to execute. Use [[logs]] in the FROM clause as the placeholder for the IIS log parquet source.",
        Category = "CustomSetting",
        DefaultValue = DefaultQuery,
        IsRequired = true )]
    [TextField( "Query Parameters",
        Key = AttributeKey.QueryParams,
        Description = "Specify the parameters required by the query using the format 'param1=value;param2=value'. Parameters matching URL page parameter values will automatically use those values. Use DuckDB named parameters in SQL like $param1.",
        Category = "CustomSetting",
        IsRequired = false )]
    [SlidingDateRangeField( "Date Range",
        Key = AttributeKey.DateRange,
        Description = "Only parquet files whose filename date stamp falls within this range will be included in the query.",
        Category = "CustomSetting",
        DefaultValue = DefaultDateRange,
        IsRequired = false,
        EnabledSlidingDateRangeTypes = "Previous, Last, Current, DateRange" )]
    [IntegerField( "Timeout Length",
        Key = AttributeKey.Timeout,
        Description = "The amount of time in seconds to allow the query to run before timing out.",
        Category = "CustomSetting",
        DefaultIntegerValue = 30,
        IsRequired = false )]
    [CustomDropdownListField( "Results Display Mode",
        Key = AttributeKey.ResultsDisplayMode,
        Description = "Determines how the results should be displayed.",
        Category = "CustomSetting",
        ListSource = "grid^Grid,lavaTemplate^Lava Template",
        DefaultValue = "grid",
        IsRequired = true )]
    [TextField( "Grid Title",
        Key = AttributeKey.GridTitle,
        Description = "The title of the grid's panel.",
        Category = "CustomSetting",
        IsRequired = false )]
    [TextField( "Selection URL",
        Key = AttributeKey.SelectionUrl,
        Description = "The URL to redirect individuals to when they click on a row in the grid. Any column's value can be used in the URL by including it in braces. For example: ~/Person/{Id}",
        Category = "CustomSetting",
        IsRequired = false )]
    [TextField( "Lava Template",
        Key = AttributeKey.LavaTemplate,
        Description = "Formatting to apply to the returned results. The template has access to rows and tables.",
        Category = "CustomSetting",
        DefaultValue = DefaultLavaTemplate,
        IsRequired = false )]
    [BooleanField( "Show Query on Page",
        Key = AttributeKey.ShowQueryOnPage,
        Description = "Shows an editable SQL editor and Run button on the page. The most recently run query is saved to the user's block preferences.",
        Category = "CustomSetting",
        DefaultBooleanValue = false,
        IsRequired = false )]

    [Rock.SystemGuid.EntityTypeGuid("ea5f4786-e909-4f1d-b12e-f6e8284987c1")]
    [Rock.SystemGuid.BlockTypeGuid("46a5cc4c-673a-46e3-b100-98104dcc0539")]
    public class LogQuery : RockBlockType, IHasCustomActions
    {
        private const string DefaultQuery = @"SELECT *
FROM [[logs]]
ORDER BY date DESC, time DESC
LIMIT 100";

        private const string DefaultLavaTemplate = @"{% assign firstRow = rows | First %}
{% if firstRow %}
    {% assign columns = firstRow.AvailableKeys %}
    <table class=""table table-condensed table-striped"">
        <thead>
            <tr>
                {% for column in columns %}
                    <th>{{ column }}</th>
                {% endfor %}
            </tr>
        </thead>
        <tbody>
            {% for row in rows %}
                <tr>
                    {% for column in columns %}
                        <td>{{ row[column] | Escape }}</td>
                    {% endfor %}
                </tr>
            {% endfor %}
        </tbody>
    </table>
{% else %}
    <div class=""alert alert-info"">No results found.</div>
{% endif %}";

        private const string DefaultDateRange = IISLogDuckDbQuery.DefaultDateRange;
        private static readonly Regex SelectionUrlRegex = new Regex( @"\{[\w\s]+\}" );

        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/logQuery.obs";

        private static class AttributeKey
        {
            public const string ParquetFolder = "ParquetFolder";
            public const string MaximumParquetFiles = "MaximumParquetFiles";
            public const string EnabledLavaCommands = "EnabledLavaCommands";
            public const string Query = "Query";
            public const string QueryParams = "QueryParams";
            public const string DateRange = "DateRange";
            public const string Timeout = "Timeout";
            public const string ResultsDisplayMode = "ResultsDisplayMode";
            public const string GridTitle = "GridTitle";
            public const string SelectionUrl = "SelectionUrl";
            public const string LavaTemplate = "LavaTemplate";
            public const string ShowQueryOnPage = "ShowQueryOnPage";
        }

        private static class NavigationUrlKey
        {
            public const string RowSelection = "RowSelection";
        }

        private static class UserPreferenceKey
        {
            public const string RecentQuery = "RecentQuery";
        }

        public override object GetObsidianBlockInitialization()
        {
            var defaultQuery = GetDefaultQuery();
            var currentQuery = GetAttributeValue( AttributeKey.ShowQueryOnPage ).AsBoolean()
                ? GetBlockPersonPreferences().GetValue( UserPreferenceKey.RecentQuery ).IfEmpty( defaultQuery )
                : defaultQuery;

            return new LogQueryInitializationBox
            {
                DefaultQuery = defaultQuery,
                CurrentQuery = currentQuery,
                DateRange = GetDateRangeBag(),
                IsLavaTemplateDisplayMode = IsLavaTemplateDisplayMode(),
                ShowQueryOnPage = GetAttributeValue( AttributeKey.ShowQueryOnPage ).AsBoolean()
            };
        }

        List<BlockCustomActionBag> IHasCustomActions.GetCustomActions( bool canEdit, bool canAdministrate )
        {
            var actions = new List<BlockCustomActionBag>();

            if ( canAdministrate )
            {
                actions.Add( new BlockCustomActionBag
                {
                    IconCssClass = "fa fa-edit",
                    Tooltip = "Settings",
                    ComponentFileUrl = "/Plugins/net_redeemertech/Security/logQueryCustomSettings.obs"
                } );
            }

            return actions;
        }

        [BlockAction]
        public BlockActionResult GetLogQueryResults( LogQueryRequestBag bag )
        {
            var query = bag?.Query;
            if ( query.IsNullOrWhiteSpace() )
            {
                query = GetDefaultQuery();
            }

            var result = GetResults( query, loadRows: true, dateRange: bag?.DateRange );
            if ( result.ErrorMessage.IsNotNullOrWhiteSpace() )
            {
                return ActionBadRequest( result.ErrorMessage );
            }

            if ( bag?.SaveUserPreference == true )
            {
                GetBlockPersonPreferences().SetValue( UserPreferenceKey.RecentQuery, query );
            }

            return ActionOk( ToResponseBag( result ) );
        }

        [BlockAction]
        public BlockActionResult GetCustomSettings()
        {
            if ( !BlockCache.IsAuthorized( Rock.Security.Authorization.ADMINISTRATE, this.RequestContext.CurrentPerson ) )
            {
                return ActionForbidden( "Not authorized to edit block settings." );
            }

            var settings = new LogQueryCustomSettingsBag
            {
                Query = GetDefaultQuery(),
                QueryParams = GetAttributeValue( AttributeKey.QueryParams ),
                DateRange = GetDateRangeBag(),
                Timeout = GetAttributeValue( AttributeKey.Timeout ).AsIntegerOrNull(),
                ResultsDisplayMode = GetResultsDisplayMode(),
                GridTitle = GetAttributeValue( AttributeKey.GridTitle ),
                SelectionUrl = GetAttributeValue( AttributeKey.SelectionUrl ),
                LavaTemplate = GetLavaTemplate(),
                ShowQueryOnPage = GetAttributeValue( AttributeKey.ShowQueryOnPage ).AsBoolean()
            };

            var options = new LogQueryCustomSettingsOptionsBag
            {
                DisplayModeItems = new List<ListItemBag> { DisplayMode.Grid, DisplayMode.LavaTemplate }
            };

            return ActionOk( new CustomSettingsBox<LogQueryCustomSettingsBag, LogQueryCustomSettingsOptionsBag>
            {
                Settings = settings,
                Options = options,
                SecurityGrantToken = new Rock.Security.SecurityGrant().ToToken()
            } );
        }

        [BlockAction]
        public BlockActionResult SaveCustomSettings( CustomSettingsBox<LogQueryCustomSettingsBag, LogQueryCustomSettingsOptionsBag> box )
        {
            if ( !BlockCache.IsAuthorized( Rock.Security.Authorization.ADMINISTRATE, this.RequestContext.CurrentPerson ) )
            {
                return ActionForbidden( "Not authorized to edit block settings." );
            }

            var block = new BlockService( this.RockContext ).Get( this.BlockId );
            block.LoadAttributes( this.RockContext );

            box.IfValidProperty( nameof( box.Settings.Query ), () => block.SetAttributeValue( AttributeKey.Query, box.Settings.Query ) );
            box.IfValidProperty( nameof( box.Settings.QueryParams ), () => block.SetAttributeValue( AttributeKey.QueryParams, box.Settings.QueryParams ) );
            box.IfValidProperty( nameof( box.Settings.DateRange ), () => block.SetAttributeValue( AttributeKey.DateRange, IISLogDuckDbQuery.ToDelimitedDateRange( box.Settings.DateRange ) ) );
            box.IfValidProperty( nameof( box.Settings.Timeout ), () => block.SetAttributeValue( AttributeKey.Timeout, box.Settings.Timeout.ToString() ) );
            box.IfValidProperty( nameof( box.Settings.ResultsDisplayMode ), () => block.SetAttributeValue( AttributeKey.ResultsDisplayMode, box.Settings.ResultsDisplayMode ) );
            box.IfValidProperty( nameof( box.Settings.GridTitle ), () => block.SetAttributeValue( AttributeKey.GridTitle, box.Settings.GridTitle ) );
            box.IfValidProperty( nameof( box.Settings.SelectionUrl ), () => block.SetAttributeValue( AttributeKey.SelectionUrl, box.Settings.SelectionUrl ) );
            box.IfValidProperty( nameof( box.Settings.LavaTemplate ), () => block.SetAttributeValue( AttributeKey.LavaTemplate, box.Settings.LavaTemplate ) );
            box.IfValidProperty( nameof( box.Settings.ShowQueryOnPage ), () => block.SetAttributeValue( AttributeKey.ShowQueryOnPage, box.Settings.ShowQueryOnPage.ToString() ) );

            block.SaveAttributeValues( this.RockContext );

            return ActionOk();
        }

        private LogQueryResults GetResults( string query, bool loadRows, int? timeout = null, SlidingDateRangeBag dateRange = null )
        {
            var result = new LogQueryResults();

            try
            {
                result.MergeFields = GetMergeFields();
                var sqlParameters = GetSqlParameters( GetAttributeValue( AttributeKey.QueryParams ).SplitDelimitedValues() );
                var resolvedQuery = query.ResolveMergeFields( result.MergeFields, GetAttributeValue( AttributeKey.EnabledLavaCommands ) );
                var defaultDateRange = GetDateRangeBag();
                var delimitedDateRange = IISLogDuckDbQuery.ToDelimitedDateRange( ValidateDateRangeBag( dateRange, defaultDateRange ) );
                var timeoutSeconds = timeout ?? GetAttributeValue( AttributeKey.Timeout ).AsIntegerOrNull() ?? 30;
                var maximumParquetFiles = GetAttributeValue( AttributeKey.MaximumParquetFiles ).AsIntegerOrNull() ?? 1000;
                var dataTable = new IISLogDuckDbQuery().Execute( resolvedQuery, delimitedDateRange, GetAttributeValue( AttributeKey.ParquetFolder ), maximumParquetFiles, timeoutSeconds, loadRows, sqlParameters );

                result.DataTable = dataTable;
                result.ActualColumnConfigurations = LoadColumnConfigurationsFromDataTable( dataTable );

                if ( IsLavaTemplateDisplayMode() )
                {
                    AddDataResultsToMergeFields( result );
                    result.LavaTemplateResults = new LavaTemplateResultsBag
                    {
                        ResultsHtml = GetLavaTemplate().ResolveMergeFields( result.MergeFields, GetAttributeValue( AttributeKey.EnabledLavaCommands ) )
                    };
                }
                else
                {
                    var gridBuilder = GetGridBuilder( result );
                    result.GridResults = new GridResultsBag
                    {
                        GridDefinition = gridBuilder.BuildDefinition(),
                        Title = GetAttributeValue( AttributeKey.GridTitle ),
                        KeyField = "uniqueKey"
                    };
                    result.GridData = loadRows ? gridBuilder.Build( dataTable.Rows.OfType<DataRow>() ) : null;
                    if ( result.GridData?.Rows != null )
                    {
                        for ( var i = 0; i < result.GridData.Rows.Count; i++ )
                        {
                            result.GridData.Rows[i]["uniqueKey"] = i;
                        }
                    }
                }
            }
            catch ( Exception ex )
            {
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        private LogQueryResponseBag ToResponseBag( LogQueryResults result )
        {
            return new LogQueryResponseBag
            {
                GridResults = result.GridResults,
                GridData = result.GridData,
                LavaTemplateResults = result.LavaTemplateResults,
                NavigationUrls = GetNavigationUrls( result )
            };
        }

        private Dictionary<string, string> GetNavigationUrls( LogQueryResults result )
        {
            var selectionUrl = GetAttributeValue( AttributeKey.SelectionUrl );
            if ( selectionUrl.IsNullOrWhiteSpace() )
            {
                return null;
            }

            var selectionUrlMatches = SelectionUrlRegex.Matches( selectionUrl );
            if ( selectionUrlMatches.Count == 0 )
            {
                return new Dictionary<string, string>
                {
                    { NavigationUrlKey.RowSelection, selectionUrl }
                };
            }

            var columns = result.ActualColumnConfigurations;
            if ( columns?.Any() != true )
            {
                return null;
            }

            foreach ( Match match in selectionUrlMatches )
            {
                var columnName = match.Value.TrimStart( '{' ).TrimEnd( '}' ).Trim();
                var gridField = columns
                    .FirstOrDefault( c => c.Name.Equals( columnName, StringComparison.OrdinalIgnoreCase ) || c.SplitCaseName.Equals( columnName, StringComparison.OrdinalIgnoreCase ) )
                    ?.CamelCaseName;

                if ( gridField.IsNullOrWhiteSpace() )
                {
                    return null;
                }

                selectionUrl = selectionUrl.Replace( match.Value, $"(({gridField}))" );
            }

            return new Dictionary<string, string>
            {
                { NavigationUrlKey.RowSelection, selectionUrl }
            };
        }

        private Dictionary<string, object> GetSqlParameters( string[] queryParams )
        {
            if ( queryParams == null || queryParams.Length == 0 )
            {
                return null;
            }

            var sqlParameters = new Dictionary<string, object>();
            foreach ( var queryParam in queryParams )
            {
                var paramParts = queryParam.Split( new[] { '=' }, 2 );
                if ( paramParts.Length != 2 )
                {
                    continue;
                }

                var queryParamName = paramParts[0].Trim();
                if ( queryParamName.IsNullOrWhiteSpace() )
                {
                    continue;
                }

                var queryParamValue = paramParts[1];

                if ( queryParamName.StartsWith( "@" ) || queryParamName.StartsWith( "$" ) )
                {
                    queryParamName = queryParamName.Substring( 1 );
                }

                var pageValue = PageParameter( queryParamName );
                if ( pageValue.IsNotNullOrWhiteSpace() )
                {
                    queryParamValue = pageValue;
                }
                else if ( queryParamName.Equals( "CurrentPersonId", StringComparison.OrdinalIgnoreCase ) && this.RequestContext.CurrentPerson != null )
                {
                    queryParamValue = this.RequestContext.CurrentPerson.Id.ToString();
                }

                sqlParameters.AddOrReplace( queryParamName, queryParamValue );
            }

            return sqlParameters;
        }

        private Dictionary<string, object> GetMergeFields()
        {
            var mergeFields = this.RequestContext.GetCommonMergeFields();
            mergeFields.AddOrReplace( "CurrentPage", this.PageCache );

            foreach ( var pageParam in this.RequestContext.GetPageParameters() )
            {
                mergeFields.AddOrReplace( pageParam.Key, pageParam.Value );
            }

            return mergeFields;
        }

        private void AddDataResultsToMergeFields( LogQueryResults result )
        {
            var rows = new List<object>();
            foreach ( DataRow row in result.DataTable.Rows )
            {
                rows.Add( new LavaRow( row ) );
            }

            var table = new Dictionary<string, object> { { "rows", rows } };
            result.MergeFields.Add( "rows", rows );
            result.MergeFields.Add( "table1", table );
            result.MergeFields.Add( "tables", new List<Dictionary<string, object>> { table } );
        }

        private GridBuilder<DataRow> GetGridBuilder( LogQueryResults result )
        {
            var gridBuilder = new GridBuilder<DataRow>().WithBlock( this );

            foreach ( var columnConfiguration in result.ActualColumnConfigurations )
            {
                var actualColumnName = columnConfiguration.ActualColumnName;
                var camelCaseName = columnConfiguration.CamelCaseName;

                gridBuilder.AddField( camelCaseName, row => ConvertGridValue( row[actualColumnName] ) );
                gridBuilder.AddDefinitionAction( definition =>
                {
                    definition.DynamicFields.Add( new DynamicFieldDefinitionBag
                    {
                        Name = camelCaseName,
                        Title = columnConfiguration.SplitCaseName,
                        ColumnType = columnConfiguration.ColumnType,
                        HideOnScreen = columnConfiguration.HideFromGrid,
                        VisiblePriority = columnConfiguration.VisiblePriority.IfEmpty( VisiblePriority.ExtraSmall.Value ),
                        Width = columnConfiguration.Width,
                        EnableFiltering = columnConfiguration.EnableFiltering,
                        ExcludeFromExport = columnConfiguration.ExcludeFromExport,
                        FieldProperties = new Dictionary<string, object>()
                    } );
                } );
            }

            return gridBuilder;
        }

        private object ConvertGridValue( object value )
        {
            if ( value == null || value == DBNull.Value )
            {
                return null;
            }

            if ( value is TimeSpan )
            {
                return value.ToString();
            }

            return value;
        }

        private List<ColumnConfigurationBag> LoadColumnConfigurationsFromDataTable( DataTable dataTable )
        {
            var columnConfigurations = new List<ColumnConfigurationBag>();
            foreach ( DataColumn dataColumn in dataTable.Columns )
            {
                var columnName = dataColumn.ColumnName;
                var column = new ColumnConfigurationBag
                {
                    Name = columnName,
                    ColumnType = GetColumnTypeFromDataType( dataColumn.DataType ),
                    VisiblePriority = VisiblePriority.ExtraSmall.Value,
                    EnableFiltering = true
                };

                column.ActualColumnName = columnName;
                columnConfigurations.Add( column );
            }

            SetColumnConfigurationNames( columnConfigurations );
            return columnConfigurations;
        }

        private string GetColumnTypeFromDataType( Type dataType )
        {
            if ( dataType == typeof( bool ) )
            {
                return ColumnType.BooleanValue;
            }
            if ( dataType == typeof( DateTime ) || dataType == typeof( DateTimeOffset ) )
            {
                return ColumnType.DateTimeValue;
            }
            if ( dataType == typeof( decimal ) )
            {
                return ColumnType.CurrencyValue;
            }
            if ( dataType == typeof( double ) || dataType == typeof( float ) || dataType == typeof( int ) || dataType == typeof( long ) || dataType == typeof( short ) || dataType == typeof( byte ) )
            {
                return ColumnType.NumberValue;
            }

            return ColumnType.TextValue;
        }

        private void SetColumnConfigurationNames( List<ColumnConfigurationBag> columnConfigurations )
        {
            columnConfigurations?.ForEach( c =>
            {
                c.Name = c.Name ?? string.Empty;
                c.SplitCaseName = c.Name.SplitCase().ReplaceWhileExists( "  ", " " );
                c.CamelCaseName = GetCamelCase( c.SplitCaseName );
            } );
        }

        private string GetCamelCase( string str )
        {
            if ( str.IsNullOrWhiteSpace() )
            {
                return str;
            }

            var words = str.Split( new[] { "_", " " }, StringSplitOptions.RemoveEmptyEntries );
            var leadWord = Regex.Replace( words[0], @"([A-Z])([A-Z]+|[a-z0-9]+)($|[A-Z]\w*)", m => m.Groups[1].Value.ToLower() + m.Groups[2].Value.ToLower() + m.Groups[3].Value );
            var tailWords = words.Skip( 1 ).Select( word => char.ToUpper( word[0] ) + word.Substring( 1 ).ToLower() ).ToArray();
            return leadWord + string.Join( string.Empty, tailWords );
        }

        private string GetDefaultQuery()
        {
            return GetAttributeValue( AttributeKey.Query ).IfEmpty( DefaultQuery );
        }

        private SlidingDateRangeBag GetDateRangeBag()
        {
            return IISLogDuckDbQuery.ToSlidingDateRangeBag( GetAttributeValue( AttributeKey.DateRange ).IfEmpty( DefaultDateRange ) )
                ?? new SlidingDateRangeBag
                {
                    RangeType = SlidingDateRangeType.Last,
                    TimeValue = 7,
                    TimeUnit = TimeUnitType.Day
                };
        }

        private static SlidingDateRangeBag ValidateDateRangeBag( SlidingDateRangeBag dateRange, SlidingDateRangeBag defaultDateRange )
        {
            if ( dateRange == null )
            {
                return defaultDateRange;
            }

            if ( dateRange.RangeType == SlidingDateRangeType.DateRange )
            {
                if ( dateRange.LowerDate.HasValue && dateRange.UpperDate.HasValue )
                {
                    if ( dateRange.UpperDate < dateRange.LowerDate )
                    {
                        dateRange.UpperDate = dateRange.LowerDate;
                    }
                }
                else if ( dateRange.LowerDate.HasValue )
                {
                    dateRange.UpperDate = dateRange.LowerDate;
                }
                else if ( dateRange.UpperDate.HasValue )
                {
                    dateRange.LowerDate = dateRange.UpperDate;
                }
                else
                {
                    return defaultDateRange;
                }
            }

            return dateRange;
        }

        private string GetLavaTemplate()
        {
            return GetAttributeValue( AttributeKey.LavaTemplate ).IfEmpty( DefaultLavaTemplate );
        }

        private string GetResultsDisplayMode()
        {
            var mode = GetAttributeValue( AttributeKey.ResultsDisplayMode );
            return mode == DisplayMode.LavaTemplate.Value ? DisplayMode.LavaTemplate.Value : DisplayMode.Grid.Value;
        }

        private bool IsLavaTemplateDisplayMode()
        {
            return GetResultsDisplayMode() == DisplayMode.LavaTemplate.Value;
        }

        private class LogQueryResults
        {
            public LogQueryResults()
            {
                MergeFields = new Dictionary<string, object>();
            }

            public string ErrorMessage { get; set; }

            public DataTable DataTable { get; set; }

            public List<ColumnConfigurationBag> ActualColumnConfigurations { get; set; }

            public GridResultsBag GridResults { get; set; }

            public GridDataBag GridData { get; set; }

            public LavaTemplateResultsBag LavaTemplateResults { get; set; }

            public Dictionary<string, object> MergeFields { get; set; }
        }

        private class LavaRow : LavaDataObject
        {
            private readonly DataRow _dataRow;

            public LavaRow( DataRow dataRow )
            {
                _dataRow = dataRow;
            }

            [LavaVisible]
            public override List<string> AvailableKeys
            {
                get
                {
                    var keys = new List<string>();
                    foreach ( DataColumn column in _dataRow.Table.Columns )
                    {
                        keys.Add( column.ColumnName );
                    }
                    return keys;
                }
            }

            protected override bool OnTryGetValue( string key, out object result )
            {
                if ( _dataRow.Table.Columns.Contains( key ) )
                {
                    result = _dataRow[key];
                    return true;
                }

                return base.OnTryGetValue(key, out result);
            }
        }

        private class DisplayMode
        {
            private static readonly ListItemBag _grid = new ListItemBag { Text = "Grid", Value = "grid" };
            public static ListItemBag Grid => _grid;

            private static readonly ListItemBag _lavaTemplate = new ListItemBag { Text = "Lava Template", Value = "lavaTemplate" };
            public static ListItemBag LavaTemplate => _lavaTemplate;
        }

        private class ColumnType
        {
            public const string BooleanValue = "boolean";
            public const string CurrencyValue = "currency";
            public const string DateValue = "date";
            public const string DateTimeValue = "dateTime";
            public const string HtmlValue = "html";
            public const string NumberValue = "number";
            public const string TextValue = "text";

            private static readonly ListItemBag _boolean = new ListItemBag { Text = "Boolean", Value = BooleanValue };
            public static ListItemBag Boolean => _boolean;
            private static readonly ListItemBag _currency = new ListItemBag { Text = "Currency", Value = CurrencyValue };
            public static ListItemBag Currency => _currency;
            private static readonly ListItemBag _date = new ListItemBag { Text = "Date", Value = DateValue };
            public static ListItemBag Date => _date;
            private static readonly ListItemBag _dateTime = new ListItemBag { Text = "Date Time", Value = DateTimeValue };
            public static ListItemBag DateTime => _dateTime;
            private static readonly ListItemBag _html = new ListItemBag { Text = "HTML", Value = HtmlValue };
            public static ListItemBag Html => _html;
            private static readonly ListItemBag _number = new ListItemBag { Text = "Number", Value = NumberValue };
            public static ListItemBag Number => _number;
            private static readonly ListItemBag _text = new ListItemBag { Text = "Text", Value = TextValue };
            public static ListItemBag Text => _text;
        }

        private class VisiblePriority
        {
            private static readonly ListItemBag _extraSmall = new ListItemBag { Text = "Extra-Small", Value = "xs" };
            public static ListItemBag ExtraSmall => _extraSmall;
            private static readonly ListItemBag _small = new ListItemBag { Text = "Small", Value = "sm" };
            public static ListItemBag Small => _small;
            private static readonly ListItemBag _medium = new ListItemBag { Text = "Medium", Value = "md" };
            public static ListItemBag Medium => _medium;
            private static readonly ListItemBag _large = new ListItemBag { Text = "Large", Value = "lg" };
            public static ListItemBag Large => _large;
            private static readonly ListItemBag _extraLarge = new ListItemBag { Text = "Extra-Large", Value = "xl" };
            public static ListItemBag ExtraLarge => _extraLarge;
        }
    }
}
