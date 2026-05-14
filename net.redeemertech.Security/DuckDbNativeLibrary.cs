using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Web.Hosting;

namespace net.redeemertech.Security
{
    public static class DuckDbNativeLibrary
    {
        private const string NativeDllName = "duckdb.dll";
        private const int LoadLibrarySearchDllLoadDir = 0x00000100;
        private const int LoadLibrarySearchDefaultDirs = 0x00001000;

        private static readonly object SyncRoot = new object();
        private static bool _isLoaded;

        public static void EnsureLoaded()
        {
            if ( _isLoaded )
            {
                return;
            }

            lock ( SyncRoot )
            {
                if ( _isLoaded )
                {
                    return;
                }

                var existingModuleHandle = GetModuleHandle( NativeDllName );
                if ( existingModuleHandle != IntPtr.Zero )
                {
                    _isLoaded = true;
                    return;
                }

                var dllPath = ResolveDuckDbDllPath();
                if ( !File.Exists( dllPath ) )
                {
                    throw new FileNotFoundException( "DuckDB native library was not found. Expected duckdb.dll under the site's DuckDB folder.", dllPath );
                }

                var moduleHandle = LoadLibraryEx( dllPath, IntPtr.Zero, LoadLibrarySearchDllLoadDir | LoadLibrarySearchDefaultDirs );
                if ( moduleHandle == IntPtr.Zero )
                {
                    throw new Win32Exception( Marshal.GetLastWin32Error(), "Unable to load the DuckDB native library." );
                }

                _isLoaded = true;
            }
        }

        private static string ResolveDuckDbDllPath()
        {
            var mappedPath = MapSitePath( "~/DuckDB/" + NativeDllName );
            if ( !string.IsNullOrWhiteSpace( mappedPath ) )
            {
                return mappedPath;
            }

            return Path.Combine( AppDomain.CurrentDomain.BaseDirectory, "DuckDB", NativeDllName );
        }

        private static string MapSitePath( string virtualPath )
        {
            try
            {
                return HostingEnvironment.MapPath( virtualPath );
            }
            catch ( InvalidOperationException )
            {
                return null;
            }
        }

        [DllImport( "kernel32", CharSet = CharSet.Unicode, SetLastError = true )]
        private static extern IntPtr GetModuleHandle( string lpModuleName );

        [DllImport( "kernel32", CharSet = CharSet.Unicode, SetLastError = true )]
        private static extern IntPtr LoadLibraryEx( string lpFileName, IntPtr hFile, int dwFlags );
    }
}
