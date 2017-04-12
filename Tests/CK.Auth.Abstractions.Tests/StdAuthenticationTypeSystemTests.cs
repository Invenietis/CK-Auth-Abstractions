using FluentAssertions;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Xunit;

namespace CK.Auth.Abstractions.Tests
{
    public class StdAuthenticationTypeSystemTests
    {
        StdAuthenticationTypeSystem _typeSystem = new StdAuthenticationTypeSystem();

        [Fact]
        public void Anonymous_exists_as_0_with_empty_DisplayName_and_Providers()
        {
            CheckAnonymousValues(_typeSystem.UserInfo.Anonymous);
        }

        [Fact]
        public void using_StdAuthenticationTypeSystem_to_convert_UserInfo_objects_from_and_to_json()
        {
            var time = new DateTime(2017, 4, 2, 14, 35, 59, DateTimeKind.Utc);
            var u = new StdUserInfo(3712, "Albert", new[] { new StdUserProviderInfo("Basic", time) });
            JObject o = _typeSystem.UserInfo.ToJObject(u);
            o["id"].Value<string>().Should().Be("3712");
            o["name"].Value<string>().Should().Be("Albert");
            ((JArray)o["providers"]).Should().HaveCount(1);
            o["providers"][0]["name"].Value<string>().Should().Be("Basic");
            o["providers"][0]["lastUsed"].Value<DateTime>().Should().Be(time);
            var u2 = _typeSystem.UserInfo.FromJObject(o);
            u2.ActorId.Should().Be(3712);
            u2.DisplayName.Should().Be("Albert");
            u2.Providers.Should().HaveCount(1);
            u2.Providers[0].Name.Should().Be("Basic");
            u2.Providers[0].LastUsed.Should().Be(time);
        }

        [Fact]
        public void test_StdAuthenticationInfo_conversion_for_JObject_and_Binary_and_Claims()
        {
            var time1 = DateTime.UtcNow.AddDays(1);
            var time2 = DateTime.UtcNow.AddDays(2);
            var u1 = new StdUserInfo(3712, "Albert", new[] { new StdUserProviderInfo("Basic", time1) });
            var u2 = new StdUserInfo(12, "Robert", new[] { new StdUserProviderInfo("Google", DateTime.UtcNow), new StdUserProviderInfo("Other", time1) });

            CheckFromTo(new StdAuthenticationInfo(_typeSystem, null, null, null, null));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem, u1, null, null, null));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem, u1, null, time1, null));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem, u1, null, time1, time2));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem, u1, u2, time1, time2));
        }

        void CheckFromTo(StdAuthenticationInfo o)
        {
            var j = _typeSystem.AuthenticationInfo.ToJObject(o);
            var o2 = _typeSystem.AuthenticationInfo.FromJObject(j);
            o2.ShouldBeEquivalentTo(o);
            // For claims, seconds are used for expiration.
            var c = _typeSystem.AuthenticationInfo.ToClaimsIdentity(o);
            var o3 = _typeSystem.AuthenticationInfo.FromClaimsIdentity(c);
            o3.ShouldBeEquivalentTo(o, options => options
                        .Using<DateTime>(ctx => ctx.Subject.Should().BeCloseTo(ctx.Expectation, 1000))
                        .WhenTypeIs<DateTime>() );
            // Binary serialization.
            MemoryStream m = new MemoryStream();
            _typeSystem.AuthenticationInfo.Write(new BinaryWriter(m), o);
            m.Position = 0;
            var o4 = _typeSystem.AuthenticationInfo.Read(new BinaryReader(m));
            o4.ShouldBeEquivalentTo(o);
        }

        [Fact]
        public void using_StdAuthenticationTypeSystem_to_convert_UserInfo_objects_from_and_to_Claims()
        {
            var time = new DateTime(2017, 4, 2, 14, 35, 59, DateTimeKind.Utc);
            var u = new StdUserInfo(3712, "Albert", new[] { new StdUserProviderInfo("Basic", time) });
            JObject o = _typeSystem.UserInfo.ToJObject(u);
            List<Claim> c = _typeSystem.UserInfo.ToClaims(u);
            var u2 = _typeSystem.UserInfo.FromClaims(c);
            u2.ActorId.Should().Be(3712);
            u2.DisplayName.Should().Be("Albert");
            u2.Providers.Should().HaveCount(1);
            u2.Providers[0].Name.Should().Be("Basic");
            u2.Providers[0].LastUsed.Should().Be(time);
        }

        static void CheckAnonymousValues(IUserInfo anonymous)
        {
            anonymous.Should().NotBeNull();
            anonymous.ActorId.Should().Be(0);
            anonymous.DisplayName.Should().BeEmpty();
            anonymous.Providers.Should().BeEmpty();
        }
    }
}
