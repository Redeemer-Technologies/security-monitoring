using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace net.redeemertech.Security.Blocks.Blocks
{
    /// <summary>
    /// Matches aggregated IIS requests to REST action route templates. Literal
    /// paths use a dictionary lookup. Parameterized paths use a method-specific
    /// literal-prefix trie and segment-count buckets before doing route matching.
    /// </summary>
    internal sealed class RestActionRequestCountMatcher
    {
        private readonly Dictionary<string, Dictionary<string, List<CompiledRoute>>> _literalPathRoutesByMethod =
            new Dictionary<string, Dictionary<string, List<CompiledRoute>>>( StringComparer.OrdinalIgnoreCase );

        private readonly Dictionary<string, PrefixNode> _parameterizedRouteRoots =
            new Dictionary<string, PrefixNode>( StringComparer.OrdinalIgnoreCase );

        public RestActionRequestCountMatcher( IEnumerable<RestActionRouteDefinition> routes )
        {
            foreach ( var route in routes ?? Enumerable.Empty<RestActionRouteDefinition>() )
            {
                var compiledRoute = CompiledRoute.Create( route );
                if ( compiledRoute == null )
                {
                    continue;
                }

                if ( !compiledRoute.HasPathParameters )
                {
                    Dictionary<string, List<CompiledRoute>> routesByPath;
                    if ( !_literalPathRoutesByMethod.TryGetValue( compiledRoute.Method, out routesByPath ) )
                    {
                        routesByPath = new Dictionary<string, List<CompiledRoute>>( StringComparer.OrdinalIgnoreCase );
                        _literalPathRoutesByMethod.Add( compiledRoute.Method, routesByPath );
                    }

                    AddToList( routesByPath, compiledRoute.Path, compiledRoute );
                    continue;
                }

                PrefixNode root;
                if ( !_parameterizedRouteRoots.TryGetValue( compiledRoute.Method, out root ) )
                {
                    root = new PrefixNode();
                    _parameterizedRouteRoots.Add( compiledRoute.Method, root );
                }

                var node = root;
                foreach ( var prefixSegment in compiledRoute.FixedPrefixSegments )
                {
                    PrefixNode child;
                    if ( !node.Children.TryGetValue( prefixSegment, out child ) )
                    {
                        child = new PrefixNode();
                        node.Children.Add( prefixSegment, child );
                    }

                    node = child;
                }

                if ( compiledRoute.MaximumSegmentCount == int.MaxValue )
                {
                    node.VariableSegmentCountRoutes.Add( compiledRoute );
                }
                else
                {
                    for ( var segmentCount = compiledRoute.MinimumSegmentCount; segmentCount <= compiledRoute.MaximumSegmentCount; segmentCount++ )
                    {
                        AddToList( node.RoutesBySegmentCount, segmentCount, compiledRoute );
                    }
                }
            }
        }

        /// <summary>
        /// Finds the single most-specific REST action represented by a logged request.
        /// Query parameters are matched separately from URL path segments and their
        /// order does not matter.
        /// </summary>
        public int? FindActionIndex( string method, string path, string query )
        {
            var request = ParsedRequest.Create( method, path, query );
            if ( request == null )
            {
                return null;
            }

            Dictionary<string, List<CompiledRoute>> routesByPath;
            List<CompiledRoute> literalCandidates;
            if ( _literalPathRoutesByMethod.TryGetValue( request.Method, out routesByPath )
                && routesByPath.TryGetValue( request.Path, out literalCandidates ) )
            {
                var literalMatch = FindBestQueryMatch( literalCandidates, request );
                if ( literalMatch != null )
                {
                    return literalMatch.ActionIndex;
                }
            }

            PrefixNode root;
            if ( !_parameterizedRouteRoots.TryGetValue( request.Method, out root ) )
            {
                return null;
            }

            CompiledRoute bestMatch = null;
            var node = root;
            bestMatch = FindBetterMatch( bestMatch, node.GetCandidates( request.PathSegments.Length ), request );

            for ( var i = 0; i < request.PathSegments.Length; i++ )
            {
                if ( !node.Children.TryGetValue( request.PathSegments[i], out node ) )
                {
                    break;
                }

                bestMatch = FindBetterMatch( bestMatch, node.GetCandidates( request.PathSegments.Length ), request );
            }

            return bestMatch == null ? ( int? ) null : bestMatch.ActionIndex;
        }

        private static CompiledRoute FindBestQueryMatch( IEnumerable<CompiledRoute> candidates, ParsedRequest request )
        {
            CompiledRoute bestMatch = null;
            foreach ( var candidate in candidates )
            {
                if ( candidate.IsQueryMatch( request )
                    && ( bestMatch == null || candidate.CompareSpecificityTo( bestMatch ) > 0 ) )
                {
                    bestMatch = candidate;
                }
            }

            return bestMatch;
        }

        private static CompiledRoute FindBetterMatch( CompiledRoute bestMatch, IEnumerable<CompiledRoute> candidates, ParsedRequest request )
        {
            foreach ( var candidate in candidates )
            {
                if ( !candidate.IsMatch( request ) )
                {
                    continue;
                }

                if ( bestMatch == null || candidate.CompareSpecificityTo( bestMatch ) > 0 )
                {
                    bestMatch = candidate;
                }
            }

            return bestMatch;
        }

        private static void AddToList<TKey>( Dictionary<TKey, List<CompiledRoute>> dictionary, TKey key, CompiledRoute route )
        {
            List<CompiledRoute> routes;
            if ( !dictionary.TryGetValue( key, out routes ) )
            {
                routes = new List<CompiledRoute>();
                dictionary.Add( key, routes );
            }

            routes.Add( route );
        }

        private sealed class PrefixNode
        {
            public Dictionary<string, PrefixNode> Children { get; } =
                new Dictionary<string, PrefixNode>( StringComparer.OrdinalIgnoreCase );

            public Dictionary<int, List<CompiledRoute>> RoutesBySegmentCount { get; } =
                new Dictionary<int, List<CompiledRoute>>();

            public List<CompiledRoute> VariableSegmentCountRoutes { get; } = new List<CompiledRoute>();

            public IEnumerable<CompiledRoute> GetCandidates( int segmentCount )
            {
                List<CompiledRoute> exactCountRoutes;
                if ( RoutesBySegmentCount.TryGetValue( segmentCount, out exactCountRoutes ) )
                {
                    foreach ( var route in exactCountRoutes )
                    {
                        yield return route;
                    }
                }

                foreach ( var route in VariableSegmentCountRoutes )
                {
                    if ( segmentCount >= route.MinimumSegmentCount )
                    {
                        yield return route;
                    }
                }
            }
        }

        private sealed class CompiledRoute
        {
            public int ActionIndex { get; private set; }
            public string Method { get; private set; }
            public string Path { get; private set; }
            public SegmentPattern[] PathSegments { get; private set; }
            public string[] FixedPrefixSegments { get; private set; }
            public QueryRequirement[] QueryRequirements { get; private set; }
            public bool HasPathParameters { get; private set; }
            public int MinimumSegmentCount { get; private set; }
            public int MaximumSegmentCount { get; private set; }
            public int LiteralPathCharacterCount { get; private set; }
            public int ConstrainedParameterCount { get; private set; }
            public int LiteralQueryCharacterCount { get; private set; }

            public static CompiledRoute Create( RestActionRouteDefinition route )
            {
                if ( route == null )
                {
                    return null;
                }

                var method = NormalizeMethod( route.Method );
                string path;
                string query;
                SplitPathAndQuery( route.RouteTemplate, out path, out query );
                path = NormalizePath( path );

                if ( method.Length == 0 || path.Length == 0 )
                {
                    return null;
                }

                var pathSegments = SplitPathSegments( path )
                    .Select( SegmentPattern.Create )
                    .ToArray();
                var queryRequirements = ParseQueryRequirements( query );
                var fixedPrefixSegments = pathSegments
                    .TakeWhile( s => s.IsLiteral )
                    .Select( s => s.LiteralValue )
                    .ToArray();

                return new CompiledRoute
                {
                    ActionIndex = route.ActionIndex,
                    Method = method,
                    Path = path,
                    PathSegments = pathSegments,
                    FixedPrefixSegments = fixedPrefixSegments,
                    QueryRequirements = queryRequirements,
                    HasPathParameters = pathSegments.Any( s => !s.IsLiteral ),
                    MinimumSegmentCount = pathSegments.Count( s => !s.IsOptional && !s.IsCatchAll ),
                    MaximumSegmentCount = pathSegments.Any( s => s.IsCatchAll ) ? int.MaxValue : pathSegments.Length,
                    LiteralPathCharacterCount = pathSegments.Sum( s => s.LiteralCharacterCount ),
                    ConstrainedParameterCount = pathSegments.Sum( s => s.ConstrainedParameterCount ),
                    LiteralQueryCharacterCount = queryRequirements.Sum( q => q.Name.Length + q.ValuePattern.LiteralCharacterCount )
                };
            }

            public bool IsMatch( ParsedRequest request )
            {
                return IsPathMatch( 0, 0, request.PathSegments ) && IsQueryMatch( request );
            }

            public int CompareSpecificityTo( CompiledRoute other )
            {
                var comparison = LiteralPathCharacterCount.CompareTo( other.LiteralPathCharacterCount );
                if ( comparison != 0 )
                {
                    return comparison;
                }

                comparison = ConstrainedParameterCount.CompareTo( other.ConstrainedParameterCount );
                if ( comparison != 0 )
                {
                    return comparison;
                }

                comparison = QueryRequirements.Length.CompareTo( other.QueryRequirements.Length );
                if ( comparison != 0 )
                {
                    return comparison;
                }

                comparison = LiteralQueryCharacterCount.CompareTo( other.LiteralQueryCharacterCount );
                if ( comparison != 0 )
                {
                    return comparison;
                }

                // Keep selection deterministic when equivalent route templates exist.
                return other.ActionIndex.CompareTo( ActionIndex );
            }

            private bool IsPathMatch( int routeIndex, int requestIndex, string[] requestSegments )
            {
                if ( routeIndex == PathSegments.Length )
                {
                    return requestIndex == requestSegments.Length;
                }

                var routeSegment = PathSegments[routeIndex];
                if ( routeSegment.IsCatchAll )
                {
                    if ( routeIndex == PathSegments.Length - 1 )
                    {
                        return true;
                    }

                    for ( var nextRequestIndex = requestIndex; nextRequestIndex <= requestSegments.Length; nextRequestIndex++ )
                    {
                        if ( IsPathMatch( routeIndex + 1, nextRequestIndex, requestSegments ) )
                        {
                            return true;
                        }
                    }

                    return false;
                }

                if ( routeSegment.IsOptional && IsPathMatch( routeIndex + 1, requestIndex, requestSegments ) )
                {
                    return true;
                }

                return requestIndex < requestSegments.Length
                    && routeSegment.IsMatch( requestSegments[requestIndex] )
                    && IsPathMatch( routeIndex + 1, requestIndex + 1, requestSegments );
            }

            public bool IsQueryMatch( ParsedRequest request )
            {
                if ( QueryRequirements.Length == 0 )
                {
                    return true;
                }

                var requestQuery = request.QueryParameters;
                foreach ( var requirement in QueryRequirements )
                {
                    List<string> values;
                    if ( !requestQuery.TryGetValue( requirement.Name, out values ) )
                    {
                        if ( requirement.IsOptional )
                        {
                            continue;
                        }

                        return false;
                    }

                    if ( !values.Any( requirement.ValuePattern.IsMatch ) )
                    {
                        return false;
                    }
                }

                return true;
            }
        }

        private sealed class ParsedRequest
        {
            private string[] _pathSegments;
            private Dictionary<string, List<string>> _queryParameters;

            public string Method { get; private set; }
            public string Path { get; private set; }
            public string Query { get; private set; }

            public string[] PathSegments
            {
                get
                {
                    if ( _pathSegments == null )
                    {
                        _pathSegments = SplitPathSegments( Path );
                    }

                    return _pathSegments;
                }
            }

            public Dictionary<string, List<string>> QueryParameters
            {
                get
                {
                    if ( _queryParameters == null )
                    {
                        _queryParameters = ParseRequestQuery( Query );
                    }

                    return _queryParameters;
                }
            }

            public static ParsedRequest Create( string method, string path, string query )
            {
                method = NormalizeMethod( method );

                string embeddedPath;
                string embeddedQuery;
                SplitPathAndQuery( path, out embeddedPath, out embeddedQuery );
                path = NormalizePath( embeddedPath );
                query = string.IsNullOrWhiteSpace( query ) ? embeddedQuery : query;

                if ( method.Length == 0 || path.Length == 0 )
                {
                    return null;
                }

                return new ParsedRequest
                {
                    Method = method,
                    Path = path,
                    Query = query
                };
            }
        }

        private sealed class SegmentPattern
        {
            private PatternPart[] Parts { get; set; }

            public bool IsLiteral { get; private set; }
            public string LiteralValue { get; private set; }
            public bool IsOptional { get; private set; }
            public bool IsCatchAll { get; private set; }
            public int LiteralCharacterCount { get; private set; }
            public int ConstrainedParameterCount { get; private set; }

            public static SegmentPattern Create( string template )
            {
                var parts = ParsePatternParts( template );
                var singleParameter = parts.Length == 1 && parts[0].Parameter != null
                    ? parts[0].Parameter
                    : null;

                return new SegmentPattern
                {
                    Parts = parts,
                    IsLiteral = parts.All( p => p.Parameter == null ),
                    LiteralValue = parts.All( p => p.Parameter == null ) ? template : null,
                    IsOptional = singleParameter != null && singleParameter.IsOptional,
                    IsCatchAll = singleParameter != null && singleParameter.IsCatchAll,
                    LiteralCharacterCount = parts.Where( p => p.Parameter == null ).Sum( p => p.Literal.Length ),
                    ConstrainedParameterCount = parts.Count( p => p.Parameter != null && p.Parameter.Constraint.Length > 0 )
                };
            }

            public bool IsMatch( string value )
            {
                if ( IsLiteral )
                {
                    return string.Equals( LiteralValue, value, StringComparison.OrdinalIgnoreCase );
                }

                if ( Parts.Length == 1 && Parts[0].Parameter != null )
                {
                    return value.Length > 0 && Parts[0].Parameter.IsConstraintMatch( value );
                }

                return MatchParts( 0, 0, value );
            }

            private bool MatchParts( int partIndex, int valueIndex, string value )
            {
                if ( partIndex == Parts.Length )
                {
                    return valueIndex == value.Length;
                }

                var part = Parts[partIndex];
                if ( part.Parameter == null )
                {
                    return StartsWithAt( value, valueIndex, part.Literal )
                        && MatchParts( partIndex + 1, valueIndex + part.Literal.Length, value );
                }

                var minimumLength = part.Parameter.IsOptional ? 0 : 1;
                for ( var endIndex = valueIndex + minimumLength; endIndex <= value.Length; endIndex++ )
                {
                    var parameterValue = value.Substring( valueIndex, endIndex - valueIndex );
                    if ( part.Parameter.IsConstraintMatch( parameterValue )
                        && MatchParts( partIndex + 1, endIndex, value ) )
                    {
                        return true;
                    }
                }

                return false;
            }
        }

        private sealed class QueryRequirement
        {
            public string Name { get; set; }
            public SegmentPattern ValuePattern { get; set; }
            public bool IsOptional { get; set; }
        }

        private sealed class PatternPart
        {
            public string Literal { get; set; }
            public ParameterPattern Parameter { get; set; }
        }

        private sealed class ParameterPattern
        {
            private string ConstraintName { get; set; }

            public bool IsOptional { get; private set; }
            public bool IsCatchAll { get; private set; }
            public string Constraint { get; private set; }

            public static ParameterPattern Create( string content )
            {
                content = ( content ?? string.Empty ).Trim();
                var isCatchAll = content.StartsWith( "*", StringComparison.Ordinal );
                content = content.TrimStart( '*' );

                var isOptional = content.EndsWith( "?", StringComparison.Ordinal );
                if ( isOptional )
                {
                    content = content.Substring( 0, content.Length - 1 );
                }

                var defaultValueIndex = content.IndexOf( '=' );
                if ( defaultValueIndex >= 0 )
                {
                    isOptional = true;
                    content = content.Substring( 0, defaultValueIndex );
                }

                var constraintIndex = content.IndexOf( ':' );
                var constraint = constraintIndex >= 0
                    ? content.Substring( constraintIndex + 1 )
                    : string.Empty;

                return new ParameterPattern
                {
                    IsOptional = isOptional,
                    IsCatchAll = isCatchAll,
                    Constraint = constraint,
                    ConstraintName = constraint.Split( ':' )[0].Trim().ToLowerInvariant()
                };
            }

            public bool IsConstraintMatch( string value )
            {
                if ( value.Length == 0 )
                {
                    return IsOptional;
                }

                if ( Constraint.Length == 0 )
                {
                    return true;
                }

                int intValue;
                long longValue;
                decimal decimalValue;
                double doubleValue;
                bool boolValue;
                DateTime dateTimeValue;
                Guid guidValue;

                if ( ConstraintName == "int" )
                {
                    return int.TryParse( value, NumberStyles.Integer, CultureInfo.InvariantCulture, out intValue );
                }

                if ( ConstraintName == "long" )
                {
                    return long.TryParse( value, NumberStyles.Integer, CultureInfo.InvariantCulture, out longValue );
                }

                if ( ConstraintName == "decimal" )
                {
                    return decimal.TryParse( value, NumberStyles.Number, CultureInfo.InvariantCulture, out decimalValue );
                }

                if ( ConstraintName == "double" || ConstraintName == "float" )
                {
                    return double.TryParse( value, NumberStyles.Float, CultureInfo.InvariantCulture, out doubleValue );
                }

                if ( ConstraintName == "bool" )
                {
                    return bool.TryParse( value, out boolValue );
                }

                if ( ConstraintName == "datetime" )
                {
                    return DateTime.TryParse( value, CultureInfo.InvariantCulture, DateTimeStyles.None, out dateTimeValue );
                }

                if ( ConstraintName == "guid" )
                {
                    return Guid.TryParse( value, out guidValue );
                }

                if ( ConstraintName == "alpha" )
                {
                    return value.All( char.IsLetter );
                }

                // Unknown/custom Web API constraints are left to the literal and
                // segment-shape checks. The plugin cannot instantiate arbitrary
                // application route constraints safely during an audit.
                return true;
            }
        }

        private static PatternPart[] ParsePatternParts( string template )
        {
            var parts = new List<PatternPart>();
            var position = 0;

            while ( position < template.Length )
            {
                var openBrace = template.IndexOf( '{', position );
                if ( openBrace < 0 )
                {
                    parts.Add( new PatternPart { Literal = template.Substring( position ) } );
                    break;
                }

                if ( openBrace > position )
                {
                    parts.Add( new PatternPart { Literal = template.Substring( position, openBrace - position ) } );
                }

                var closeBrace = template.IndexOf( '}', openBrace + 1 );
                if ( closeBrace < 0 )
                {
                    parts.Add( new PatternPart { Literal = template.Substring( openBrace ) } );
                    break;
                }

                parts.Add( new PatternPart
                {
                    Parameter = ParameterPattern.Create( template.Substring( openBrace + 1, closeBrace - openBrace - 1 ) )
                } );
                position = closeBrace + 1;
            }

            if ( parts.Count == 0 )
            {
                parts.Add( new PatternPart { Literal = string.Empty } );
            }

            return parts.ToArray();
        }

        private static QueryRequirement[] ParseQueryRequirements( string query )
        {
            if ( string.IsNullOrWhiteSpace( query ) || query == "-" )
            {
                return new QueryRequirement[0];
            }

            return query.TrimStart( '?' )
                .Split( new[] { '&' }, StringSplitOptions.RemoveEmptyEntries )
                .Select( item =>
                {
                    var equalsIndex = item.IndexOf( '=' );
                    var name = equalsIndex < 0 ? item : item.Substring( 0, equalsIndex );
                    var value = equalsIndex < 0 ? string.Empty : item.Substring( equalsIndex + 1 );
                    var valuePattern = SegmentPattern.Create( SafeUrlDecode( value ) );

                    return new QueryRequirement
                    {
                        Name = SafeUrlDecode( name ),
                        ValuePattern = valuePattern,
                        IsOptional = valuePattern.IsOptional
                    };
                } )
                .Where( q => q.Name.Length > 0 )
                .ToArray();
        }

        private static Dictionary<string, List<string>> ParseRequestQuery( string query )
        {
            var result = new Dictionary<string, List<string>>( StringComparer.OrdinalIgnoreCase );
            if ( string.IsNullOrWhiteSpace( query ) || query == "-" )
            {
                return result;
            }

            foreach ( var item in query.TrimStart( '?' ).Split( new[] { '&' }, StringSplitOptions.RemoveEmptyEntries ) )
            {
                var equalsIndex = item.IndexOf( '=' );
                var name = SafeUrlDecode( equalsIndex < 0 ? item : item.Substring( 0, equalsIndex ) );
                var value = SafeUrlDecode( equalsIndex < 0 ? string.Empty : item.Substring( equalsIndex + 1 ) );
                if ( name.Length == 0 )
                {
                    continue;
                }

                List<string> values;
                if ( !result.TryGetValue( name, out values ) )
                {
                    values = new List<string>();
                    result.Add( name, values );
                }

                values.Add( value );
            }

            return result;
        }

        private static string SafeUrlDecode( string value )
        {
            value = ( value ?? string.Empty ).Replace( "+", " " );
            try
            {
                return Uri.UnescapeDataString( value );
            }
            catch ( UriFormatException )
            {
                return value;
            }
        }

        private static bool StartsWithAt( string value, int index, string expected )
        {
            return index + expected.Length <= value.Length
                && string.Compare( value, index, expected, 0, expected.Length, StringComparison.OrdinalIgnoreCase ) == 0;
        }

        private static string NormalizeMethod( string method )
        {
            return ( method ?? string.Empty ).Trim().ToUpperInvariant();
        }

        private static string NormalizePath( string path )
        {
            return ( path ?? string.Empty ).Trim().Trim( '/' );
        }

        private static string[] SplitPathSegments( string path )
        {
            return path.Split( new[] { '/' }, StringSplitOptions.RemoveEmptyEntries );
        }

        private static void SplitPathAndQuery( string value, out string path, out string query )
        {
            value = value ?? string.Empty;
            var queryIndex = -1;
            var braceDepth = 0;

            for ( var i = 0; i < value.Length; i++ )
            {
                if ( value[i] == '{' )
                {
                    braceDepth++;
                }
                else if ( value[i] == '}' && braceDepth > 0 )
                {
                    braceDepth--;
                }
                else if ( value[i] == '?' && braceDepth == 0 )
                {
                    queryIndex = i;
                    break;
                }
            }

            if ( queryIndex < 0 )
            {
                path = value;
                query = string.Empty;
                return;
            }

            path = value.Substring( 0, queryIndex );
            query = value.Substring( queryIndex + 1 );
        }
    }

    internal sealed class RestActionRouteDefinition
    {
        public int ActionIndex { get; set; }
        public string Method { get; set; }
        public string RouteTemplate { get; set; }
    }
}
