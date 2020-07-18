using NUnitLite;
using System.Globalization;
using System.Reflection;

namespace SqlCallDemo.NetCore.Tests
{
    public static class Program
    {
        public static int Main( string[] args )
        {
            return new AutoRun( typeof( Program ).Assembly ).Execute( args );
        }
    }
}
