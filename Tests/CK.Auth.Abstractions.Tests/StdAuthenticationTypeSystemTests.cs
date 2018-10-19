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
        StdAuthenticationTypeSystem _typeSystem = new StdAuthenticationTypeSystem( new StdUserInfoType() );

        [Test]
        public void Anonymous_exists_as_0_with_empty_DisplayName_and_Providers()
        {
            CheckAnonymousValues( _typeSystem.UserInfoType.Anonymous );
        }

        [Test]
        public void FromClaimsIdentity_handles_only_AuthenticationType_or_AuthenticationTypeSimple_ClaimsIdentity_AuthenticationType()
        {
            var u = new StdUserInfo( 345, "Kilo" );
            var a = new StdAuthenticationInfo( _typeSystem.UserInfoType, u, DateTime.UtcNow.AddDays( 1 ) );
            var cFull = _typeSystem.ToClaimsIdentity( a, userInfoOnly: false );
            cFull.AuthenticationType.Should().Be( _typeSystem.ClaimAuthenticationType );
            var cLight = _typeSystem.ToClaimsIdentity( a, userInfoOnly: true );
            cLight.AuthenticationType.Should().Be( _typeSystem.ClaimAuthenticationTypeSimple );

            _typeSystem.FromClaimsIdentity( cFull ).Should().NotBeNull();
            _typeSystem.FromClaimsIdentity( cLight ).Should().NotBeNull();

            var other = new ClaimsIdentity( cFull.Claims, "Other" );
            _typeSystem.FromClaimsIdentity( other ).Should().BeNull();
        }

        [Test]
        public void using_StdAuthenticationTypeSystem_to_convert_UserInfo_objects_from_and_to_json()
        {
            var time = new DateTime( 2017, 4, 2, 14, 35, 59, DateTimeKind.Utc );
            var u = new StdUserInfo( 3712, "Albert", new StdUserSchemeInfo( "Basic", time ) );
            JObject o = _typeSystem.UserInfoType.ToJObject( u );
            o["id"].Value<string>().Should().Be( "3712" );
            o["name"].Value<string>().Should().Be( "Albert" );
            ((JArray)o["schemes"]).Should().HaveCount( 1 );
            o["schemes"][0]["name"].Value<string>().Should().Be( "Basic" );
            o["schemes"][0]["lastUsed"].Value<DateTime>().Should().Be( time );
            var u2 = _typeSystem.UserInfoType.FromJObject( o );
            u2.UserId.Should().Be( 3712 );
            u2.UserName.Should().Be( "Albert" );
            u2.Schemes.Should().HaveCount( 1 );
            u2.Schemes[0].Name.Should().Be( "Basic" );
            u2.Schemes[0].LastUsed.Should().Be( time );
        }

        [Test]
        public void test_StdAuthenticationInfo_conversion_for_JObject_and_Binary_and_Claims()
        {
            var time1 = DateTime.UtcNow.AddDays( 1 );
            var time2 = DateTime.UtcNow.AddDays( 2 );
            var u1 = new StdUserInfo( 3712, "Albert", new StdUserSchemeInfo( "Basic", time1 ) );
            var u2 = new StdUserInfo( 12, "Robert", new StdUserSchemeInfo( "Google", DateTime.UtcNow ), new StdUserSchemeInfo( "Other", time1 ) );

            CheckFromTo( new StdAuthenticationInfo( _typeSystem.UserInfoType, null, null, null, null ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem.UserInfoType, u1, null, null, null ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem.UserInfoType, u1, null, time1, null ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem.UserInfoType, u1, null, time2, time1 ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem.UserInfoType, u1, u2, time2, time1 ) );
            CheckFromTo( new StdAuthenticationInfo( _typeSystem.UserInfoType, u1, u2, time2, null ) );
        }

        void CheckFromTo( StdAuthenticationInfo o )
        {
            var j = _typeSystem.ToJObject( o );
            var o2 = _typeSystem.FromJObject( j );
            if( o.IsNullOrNone() ) o2.Should().Match<StdAuthenticationInfo>( x => x.IsNullOrNone() );
            else o2.Should().BeEquivalentTo( o );
            // For claims, seconds are used for expiration.
            // Using full export.
            var c = _typeSystem.ToClaimsIdentity( o, userInfoOnly: false );
            var o3 = _typeSystem.FromClaimsIdentity( c );
            if( o.IsNullOrNone() ) o3.Should().Match<StdAuthenticationInfo>( x => x.IsNullOrNone() );
            else o3.Should().BeEquivalentTo( o, options => options
                         .Using<DateTime>( ctx => ctx.Subject.Should().BeCloseTo( ctx.Expectation, 1000 ) )
                         .WhenTypeIs<DateTime>() );
            // Using userInfoOnly export.
            var cSafe = _typeSystem.ToClaimsIdentity( o, userInfoOnly: true );
            var oSafe = _typeSystem.FromClaimsIdentity( cSafe );
            var userOnly = new StdAuthenticationInfo( _typeSystem.UserInfoType, o.User, o.Expires, o.CriticalExpires );
            if( userOnly.IsNullOrNone() ) oSafe.Should().Match<StdAuthenticationInfo>( x => x.IsNullOrNone() );
            else
            {
                oSafe.Should().BeEquivalentTo( userOnly, options => options
                         .Using<DateTime>( ctx => ctx.Subject.Should().BeCloseTo( ctx.Expectation, 1000 ) )
                         .WhenTypeIs<DateTime>() );
            }
            // Binary serialization.
            MemoryStream m = new MemoryStream();
            _typeSystem.Write( new BinaryWriter( m ), o );
            m.Position = 0;
            var o4 = _typeSystem.Read( new BinaryReader( m ) );
            if( o.IsNullOrNone() ) o4.Should().BeNull();
            else o4.Should().BeEquivalentTo( o );
        }

        [Test]
        public void using_StdAuthenticationTypeSystem_to_convert_UserInfo_objects_from_and_to_Claims()
        {
            var time = new DateTime( 2017, 4, 2, 14, 35, 59, DateTimeKind.Utc );
            var u = new StdUserInfo( 3712, "Albert", new[] { new StdUserSchemeInfo( "Basic", time ) } );
            JObject o = _typeSystem.UserInfoType.ToJObject( u );
            List<Claim> c = _typeSystem.UserInfoType.ToClaims( u );
            var u2 = _typeSystem.UserInfoType.FromClaims( c );
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
    }
}
