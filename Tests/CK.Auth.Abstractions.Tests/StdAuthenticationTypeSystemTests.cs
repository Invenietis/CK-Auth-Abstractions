using FluentAssertions;
using Newtonsoft.Json.Linq;
using System;
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
            o["actorId"].Value<string>().Should().Be("3712");
            o["displayName"].Value<string>().Should().Be("Albert");
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
        public void test_StdAuthenticationInfo_conversion_for_JObject_and_Claims()
        {
            var time1 = DateTime.UtcNow.AddDays(1);
            var time2 = DateTime.UtcNow.AddDays(2);
            var u1 = new StdUserInfo(3712, "Albert", new[] { new StdUserProviderInfo("Basic", time1) });
            var u2 = new StdUserInfo(12, "Robert", new[] { new StdUserProviderInfo("Google", DateTime.UtcNow), new StdUserProviderInfo("Other", time1) });

            CheckFromTo(new StdAuthenticationInfo(_typeSystem.UserInfo.Anonymous, null, null, null, null));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem.UserInfo.Anonymous, u1, null, null, null));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem.UserInfo.Anonymous, u1, null, time1, null));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem.UserInfo.Anonymous, u1, null, time1, time2));
            CheckFromTo(new StdAuthenticationInfo(_typeSystem.UserInfo.Anonymous, u1, u2, time1, time2));
        }

        void CheckFromTo(StdAuthenticationInfo o)
        {
            var j = _typeSystem.AuthenticationInfo.ToJObject(o);
            var o2 = _typeSystem.AuthenticationInfo.FromJObject(j);
            o2.ShouldBeEquivalentTo(o);
            // For claims, seconds are used for expiration.
            var c = _typeSystem.AuthenticationInfo.ToClaimsPrincipal(o);
            var o3 = _typeSystem.AuthenticationInfo.FromClaimsPrincipal(c);
            o3.ShouldBeEquivalentTo(o, options => options
                        .Using<DateTime>(ctx => ctx.Subject.Should().BeCloseTo(ctx.Expectation, 1000))
                        .WhenTypeIs<DateTime>() );
        }

        [Fact]
        public void StdAuthenticationInfo_expirations_are_checked()
        {
            var time0 = new DateTime(2000, 1, 1, 14, 35, 59, DateTimeKind.Utc);
            var time1 = new DateTime(2001, 2, 2, 14, 35, 59, DateTimeKind.Utc);
            var time2 = new DateTime(2002, 3, 3, 14, 35, 59, DateTimeKind.Utc);
            var time3 = new DateTime(2003, 4, 4, 14, 35, 59, DateTimeKind.Utc);
            var u = new StdUserInfo(3712, "Albert", null);

            // Challenge Expires only.
            {
                var a = new StdAuthenticationInfo(_typeSystem.UserInfo.Anonymous, u, null, time2, null, time0);
                a.Level.Should().Be(AuthLevel.Normal);
                a.User.ActorId.Should().Be(u.ActorId);
                a.CriticalExpires.Should().BeNull();

                var aNotExpired = a.CheckExpiration(time1);
                aNotExpired.Should().BeSameAs(a);

                var aExpired = a.CheckExpiration(time2);
                aExpired.Level.Should().Be(AuthLevel.Unsafe);
                aExpired.User.ActorId.Should().Be(0);
                aExpired.UnsafeUser.ActorId.Should().Be(u.ActorId);

                aExpired = a.CheckExpiration(time3);
                aExpired.Level.Should().Be(AuthLevel.Unsafe);
                aExpired.User.ActorId.Should().Be(0);
                aExpired.UnsafeUser.ActorId.Should().Be(u.ActorId);
            }
            // Challenge CriticalExpires.
            {
                var a = new StdAuthenticationInfo(_typeSystem.UserInfo.Anonymous, u, null, time2, time1, time0);
                a.Level.Should().Be(AuthLevel.Critical);

                var noChange = a.CheckExpiration(time0);
                noChange.Should().BeSameAs(a);

                var toNormal = a.CheckExpiration(time1);
                toNormal.Level.Should().Be(AuthLevel.Normal);

                var toUnsafe = a.CheckExpiration(time2);
                toUnsafe.Level.Should().Be(AuthLevel.Unsafe);
                toUnsafe = a.CheckExpiration(time3);
                toUnsafe.Level.Should().Be(AuthLevel.Unsafe);
            }
        }

        [Fact]
        public void using_StdAuthenticationTypeSystem_to_convert_UserInfo_objects_from_and_to_ClaimsIdentity()
        {
            var time = new DateTime(2017, 4, 2, 14, 35, 59, DateTimeKind.Utc);
            var u = new StdUserInfo(3712, "Albert", new[] { new StdUserProviderInfo("Basic", time) });
            JObject o = _typeSystem.UserInfo.ToJObject(u);
            ClaimsIdentity c = _typeSystem.UserInfo.ToClaimsIdentity(u);
            var u2 = _typeSystem.UserInfo.FromClaimsIdentity(c);
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
