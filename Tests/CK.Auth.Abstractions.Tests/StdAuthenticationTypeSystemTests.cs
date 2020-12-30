using FluentAssertions;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using NUnit.Framework;

namespace CK.Auth.Abstractions.Tests
{
    [TestFixture]
    public class StdAuthenticationTypeSystemTests
    {
        StdAuthenticationTypeSystem _typeSystem = new StdAuthenticationTypeSystem();

        [Test]
        public void Anonymous_exists_as_0_with_empty_DisplayName_and_Providers()
        {
            CheckAnonymousValues( _typeSystem.UserInfo.Anonymous );
        }

        [Test]
        public void FromClaimsIdentity_handles_only_AuthenticationType_or_AuthenticationTypeSimple_ClaimsIdentity_AuthenticationType()
        {
            var u = _typeSystem.UserInfo.Create( 345, "Kilo" );
            var a = _typeSystem.AuthenticationInfo.Create( u, DateTime.UtcNow.AddDays( 1 ) );
            var cFull = _typeSystem.AuthenticationInfo.ToClaimsIdentity( a, userInfoOnly: false );
            cFull.AuthenticationType.Should().Be( _typeSystem.ClaimAuthenticationType );
            var cLight = _typeSystem.AuthenticationInfo.ToClaimsIdentity( a, userInfoOnly: true );
            cLight.AuthenticationType.Should().Be( _typeSystem.ClaimAuthenticationTypeSimple );

            _typeSystem.AuthenticationInfo.FromClaimsIdentity( cFull ).Should().NotBeNull();
            _typeSystem.AuthenticationInfo.FromClaimsIdentity( cLight ).Should().NotBeNull();

            var other = new ClaimsIdentity( cFull.Claims, "Other" );
            _typeSystem.AuthenticationInfo.FromClaimsIdentity( other ).Should().BeNull();
        }

        [Test]
        public void using_StdAuthenticationTypeSystem_to_convert_UserInfo_objects_from_and_to_json()
        {
            var time = new DateTime( 2017, 4, 2, 14, 35, 59, DateTimeKind.Utc );
            var u = _typeSystem.UserInfo.Create( 3712, "Albert", new[] { new StdUserSchemeInfo( "Basic", time ) } );
            JObject o = _typeSystem.UserInfo.ToJObject( u );
            o["id"].Value<string>().Should().Be( "3712" );
            o["name"].Value<string>().Should().Be( "Albert" );
            ((JArray)o["schemes"]).Should().HaveCount( 1 );
            o["schemes"][0]["name"].Value<string>().Should().Be( "Basic" );
            o["schemes"][0]["lastUsed"].Value<DateTime>().Should().Be( time );
            var u2 = _typeSystem.UserInfo.FromJObject( o );
            u2.UserId.Should().Be( 3712 );
            u2.UserName.Should().Be( "Albert" );
            u2.Schemes.Should().HaveCount( 1 );
            u2.Schemes[0].Name.Should().Be( "Basic" );
            u2.Schemes[0].LastUsed.Should().Be( time );
        }

        [Test]
        public void using_StdAuthenticationTypeSystem_to_convert_UserInfo_objects_from_and_to_Claims()
        {
            var time = new DateTime( 2017, 4, 2, 14, 35, 59, DateTimeKind.Utc );
            var u = new StdUserInfo( 3712, "Albert", new[] { new StdUserSchemeInfo( "Basic", time ) } );
            JObject o = _typeSystem.UserInfo.ToJObject( u );
            List<Claim> c = _typeSystem.UserInfo.ToClaims( u );
            var u2 = _typeSystem.UserInfo.FromClaims( c );
            u2.UserId.Should().Be( 3712 );
            u2.UserName.Should().Be( "Albert" );
            u2.Schemes.Should().HaveCount( 1 );
            u2.Schemes[0].Name.Should().Be( "Basic" );
            u2.Schemes[0].LastUsed.Should().Be( time );
        }

        static void CheckAnonymousValues( IUserInfo anonymous )
        {
            anonymous.Should().NotBeNull();
            anonymous.UserId.Should().Be( 0 );
            anonymous.UserName.Should().BeEmpty();
            anonymous.Schemes.Should().BeEmpty();
        }

        [Test]
        public void StdAuthenticationInfo_creates_anonymous_with_specific_device()
        {
            _typeSystem.AuthenticationInfo.None.DeviceId.Should().BeEmpty();
            _typeSystem.AuthenticationInfo.Create( null ).Should().BeSameAs( _typeSystem.AuthenticationInfo.None );
            _typeSystem.AuthenticationInfo.Create( null, deviceId: "" ).Should().BeSameAs( _typeSystem.AuthenticationInfo.None );

            var withDevice = _typeSystem.AuthenticationInfo.Create( null, deviceId: "Yep" );
            withDevice.Should().NotBeSameAs( _typeSystem.AuthenticationInfo.None );
            withDevice.DeviceId.Should().Be( "Yep" );

            var withWhiteDevice = _typeSystem.AuthenticationInfo.Create( null, deviceId: " " );
            withWhiteDevice.Should().NotBeSameAs( _typeSystem.AuthenticationInfo.None );
            withWhiteDevice.DeviceId.Should().Be( " " );
        }

        [Test]
        public void test_StdAuthenticationInfo_conversion_for_JObject_and_Binary_and_Claims()
        {
            var time1 = DateTime.UtcNow.AddDays( 1 );
            var time2 = DateTime.UtcNow.AddDays( 2 );
            var u1 = _typeSystem.UserInfo.Create( 3712, "Albert", new[] { new StdUserSchemeInfo( "Basic", time1 ) } );
            var u2 = _typeSystem.UserInfo.Create( 12, "Robert", new[] { new StdUserSchemeInfo( "Google", DateTime.UtcNow ), new StdUserSchemeInfo( "Other", time1 ) } );

            CheckFromTo( new StdAuthenticationInfo( _typeSystem, null, null, null, null, "A device..." ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem, u1, null, null, null, "76754" ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem, u1, null, time1, null, deviceId: Guid.NewGuid().ToString() ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem, u1, null, time2, time1 ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem, u1, u2, time2, time1, "device" ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem, u1, u2, time2, null ) );
        }

        void CheckFromTo( StdAuthenticationInfo o )
        {
            var j = _typeSystem.AuthenticationInfo.ToJObject( o );
            var o2 = _typeSystem.AuthenticationInfo.FromJObject( j );
            if( o == null ) o2.Should().BeNull();
            else o2.Should().BeEquivalentTo( o );
            // For claims, seconds are used for expiration.
            // Using full export ("CKA").
            var c = _typeSystem.AuthenticationInfo.ToClaimsIdentity( o, userInfoOnly: false );
            var o3 = _typeSystem.AuthenticationInfo.FromClaimsIdentity( c );
            if( o == null ) o3.Should().BeNull();
            else o3.Should().BeEquivalentTo( o, options => options
                         .Using<DateTime>( ctx => ctx.Subject.Should().BeCloseTo( ctx.Expectation, 1000 ) )
                         .WhenTypeIs<DateTime>() );
            // Using userInfoOnly export ("CKS-S").
            var cSafe = _typeSystem.AuthenticationInfo.ToClaimsIdentity( o, userInfoOnly: true );
            var oSafe = _typeSystem.AuthenticationInfo.FromClaimsIdentity( cSafe );
            var userOnly = _typeSystem.AuthenticationInfo.Create( o.User, o.Expires, o.CriticalExpires, o.DeviceId );
            if( userOnly == null ) oSafe.Should().BeNull();
            else
            {
                oSafe.Should().BeEquivalentTo( userOnly, options => options
                         .Using<DateTime>( ctx => ctx.Subject.Should().BeCloseTo( ctx.Expectation, 1000 ) )
                         .WhenTypeIs<DateTime>() );
            }
            // Binary serialization.
            MemoryStream m = new MemoryStream();
            _typeSystem.AuthenticationInfo.Write( new BinaryWriter( m ), o );
            m.Position = 0;
            var o4 = _typeSystem.AuthenticationInfo.Read( new BinaryReader( m ) );
            if( o == null ) o4.Should().BeNull();
            else o4.Should().BeEquivalentTo( o );
        }

    }
}
