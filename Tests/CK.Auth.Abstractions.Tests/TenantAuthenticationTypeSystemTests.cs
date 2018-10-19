using CK.Auth.Abstractions.Tests.SpecializedAuth;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace CK.Auth.Abstractions.Tests
{
    [TestFixture]
    public class TenantAuthenticationTypeSystemTests
    {
        [Test]
        public void io_idempotence_checks_for_StdUserInfo()
        {
            var f1 = DateTime.UtcNow.AddHours( 1 );
            var f2 = DateTime.UtcNow.AddDays( 187 );
            var t = new TenantAuthenticationTypeSystem<StdUserInfo>( new StdUserInfoType() );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, null );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.None );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.Create( 3712, CreateRandomStdUser(), null, f1, f2 ) );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.Create( -34, null, CreateRandomStdUser(), f2, f1 ) );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.Create( 38675, CreateRandomStdUser(), CreateRandomStdUser(), f2, f1 ) );
        }

        StdUserInfo CreateRandomStdUser()
        {
            return new StdUserInfo( Environment.TickCount, Guid.NewGuid().ToString() );
        }

        [Test]
        public void io_idempotence_checks_for_XLCIDUserInfo()
        {
            var f1 = DateTime.UtcNow.AddHours( 1 );
            var f2 = DateTime.UtcNow.AddDays( 187 );
            var t = new TenantAuthenticationTypeSystem<XLCIDUserInfo>( new XLCIDUserInfoType() );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, null );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.None );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.Create( 3712, CreateRandomXLCIDUser(), null, f1, f2 ) );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.Create( -34, null, CreateRandomXLCIDUser(), f2, f1 ) );
            StdAuthenticationTypeSystemTests.CheckIdempotence( t, t.Create( 38675, CreateRandomXLCIDUser(), CreateRandomXLCIDUser(), f2, f1 ) );
        }

        XLCIDUserInfo CreateRandomXLCIDUser()
        {
            return new XLCIDUserInfo( Environment.TickCount % 199, Environment.TickCount, Guid.NewGuid().ToString() );
        }

    }
}
