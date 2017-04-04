using FluentAssertions;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Claims;
using Xunit;

namespace CK.Auth.Abstractions.Tests
{
    public class StdAuthenticationAndUserInfoTests
    {
        IAuthenticationTypeSystem _typeSystem = new StdAuthenticationTypeSystem();
        IUserInfo _albert = new StdUserInfo(3712, "Albert", null);
        IUserInfo _robert = new StdUserInfo(12, "Robert", null);

        [Fact]
        public void StdUserInfo_constructor_check_anonymous_constraints()
        {
            Action fail;
            fail = () => new StdUserInfo(0, "Name for Anonymous");
            fail.ShouldThrow<ArgumentException>();
            fail = () => new StdUserInfo(3712, "");
            fail.ShouldThrow<ArgumentException>();
        }

        [Fact]
        public void StdAuthenticationInfo_expirations_can_easily_be_checked()
        {
            var time0 = new DateTime(2000, 1, 1, 14, 35, 59, DateTimeKind.Utc);
            var time1 = new DateTime(2001, 2, 2, 14, 35, 59, DateTimeKind.Utc);
            var time2 = new DateTime(2002, 3, 3, 14, 35, 59, DateTimeKind.Utc);
            var time3 = new DateTime(2003, 4, 4, 14, 35, 59, DateTimeKind.Utc);

            // Challenge Expires only.
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert, null, time2, null, time0);
                a.Level.Should().Be(AuthLevel.Normal);
                a.User.ActorId.Should().Be(_albert.ActorId);
                a.CriticalExpires.Should().BeNull();

                var aNotExpired = a.CheckExpiration(time1);
                aNotExpired.Should().BeSameAs(a);

                var aExpired = a.CheckExpiration(time2);
                aExpired.Level.Should().Be(AuthLevel.Unsafe);
                aExpired.User.ActorId.Should().Be(0);
                aExpired.UnsafeUser.ActorId.Should().Be(_albert.ActorId);

                aExpired = a.CheckExpiration(time3);
                aExpired.Level.Should().Be(AuthLevel.Unsafe);
                aExpired.User.ActorId.Should().Be(0);
                aExpired.UnsafeUser.ActorId.Should().Be(_albert.ActorId);
            }
            // Challenge CriticalExpires.
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert, null, time2, time1, time0);
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
        public void Unsafe_level_constructor_for_IAuthenticationInfo()
        {
            var a = new StdAuthenticationInfo(_typeSystem, _albert);
            a.Level.Should().Be(AuthLevel.Unsafe);
            a.User.Should().BeSameAs(_typeSystem.UserInfo.Anonymous);
            a.ActualUser.Should().BeSameAs(_typeSystem.UserInfo.Anonymous);
            a.UnsafeUser.Should().BeSameAs(_albert);
            a.UnsafeActualUser.Should().BeSameAs(_albert);
            a.IsImpersonated.Should().Be(false);
        }

        [Fact]
        public void Normal_level_constructor_for_IAuthenticationInfo()
        {
            {
                var time = DateTime.UtcNow.AddDays(1);
                var a = new StdAuthenticationInfo(_typeSystem, _albert, time);
                a.Level.Should().Be(AuthLevel.Normal);
                a.User.Should().BeSameAs(_albert);
                a.ActualUser.Should().BeSameAs(_albert);
                a.UnsafeUser.Should().BeSameAs(_albert);
                a.UnsafeActualUser.Should().BeSameAs(_albert);
                a.IsImpersonated.Should().Be(false);
            }
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert, DateTime.UtcNow);
                a.Level.Should().Be(AuthLevel.Unsafe);
                a.User.Should().BeSameAs(_typeSystem.UserInfo.Anonymous);
                a.ActualUser.Should().BeSameAs(_typeSystem.UserInfo.Anonymous);
                a.UnsafeUser.Should().BeSameAs(_albert);
                a.UnsafeActualUser.Should().BeSameAs(_albert);
                a.IsImpersonated.Should().Be(false);
            }
        }

        [Fact]
        public void Critical_level_constructor_for_IAuthenticationInfo()
        {
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert, 
                                DateTime.UtcNow.AddDays(1),
                                DateTime.UtcNow.AddDays(2) );
                a.Level.Should().Be(AuthLevel.Critical);
                a.User.Should().BeSameAs(_albert);
                a.ActualUser.Should().BeSameAs(_albert);
                a.UnsafeUser.Should().BeSameAs(_albert);
                a.UnsafeActualUser.Should().BeSameAs(_albert);
                a.IsImpersonated.Should().Be(false);
            }
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert,
                                DateTime.UtcNow.AddDays(1),
                                DateTime.UtcNow.AddDays(-1));
                a.Level.Should().Be(AuthLevel.Normal);
                a.User.Should().BeSameAs(_albert);
                a.ActualUser.Should().BeSameAs(_albert);
                a.UnsafeUser.Should().BeSameAs(_albert);
                a.UnsafeActualUser.Should().BeSameAs(_albert);
                a.IsImpersonated.Should().Be(false);
            }
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert,
                                DateTime.UtcNow,
                                DateTime.UtcNow.AddDays(-1));
                a.Level.Should().Be(AuthLevel.Unsafe);
                a.User.Should().BeSameAs(_typeSystem.UserInfo.Anonymous);
                a.ActualUser.Should().BeSameAs(_typeSystem.UserInfo.Anonymous);
                a.UnsafeUser.Should().BeSameAs(_albert);
                a.UnsafeActualUser.Should().BeSameAs(_albert);
                a.IsImpersonated.Should().Be(false);
            }
        }

        [Fact]
        public void impersonation_works_the_same_for_all_levels_except_none()
        {
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert);
                a.Level.Should().Be(AuthLevel.Unsafe);
                a.IsImpersonated.Should().Be(false);

                var imp = a.Impersonate(_robert);
                imp.IsImpersonated.Should().Be(true);
                imp.UnsafeActualUser.Should().BeSameAs(_albert);
                imp.UnsafeUser.Should().BeSameAs(_robert);

                var back = imp.ClearImpersonation();
                back.IsImpersonated.Should().Be(false);
                back.UnsafeActualUser.Should().BeSameAs(_albert);
                back.UnsafeUser.Should().BeSameAs(_albert);
            }
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert, DateTime.UtcNow.AddDays(1));
                a.Level.Should().Be(AuthLevel.Normal);
                a.IsImpersonated.Should().Be(false);

                var imp = a.Impersonate(_robert);
                imp.IsImpersonated.Should().Be(true);
                imp.ActualUser.Should().BeSameAs(_albert);
                imp.User.Should().BeSameAs(_robert);
                imp.UnsafeActualUser.Should().BeSameAs(_albert);
                imp.UnsafeUser.Should().BeSameAs(_robert);

                var back = imp.ClearImpersonation();
                back.IsImpersonated.Should().Be(false);
                back.ActualUser.Should().BeSameAs(_albert);
                back.User.Should().BeSameAs(_albert);
                back.UnsafeActualUser.Should().BeSameAs(_albert);
                back.UnsafeUser.Should().BeSameAs(_albert);
            }
        }


    }
}
