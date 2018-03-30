using FluentAssertions;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Claims;
using NUnit.Framework;

namespace CK.Auth.Abstractions.Tests
{
    [TestFixture]
    public class StdAuthenticationAndUserInfoTests
    {
        static readonly IAuthenticationTypeSystem _typeSystem;
        static readonly IUserInfo _albert;
        static readonly IUserInfo _robert;
        static readonly DateTime _time0;
        static readonly DateTime _time1;
        static readonly DateTime _time2;
        static readonly DateTime _time3;

        static StdAuthenticationAndUserInfoTests()
        {
            _typeSystem = new StdAuthenticationTypeSystem();
            _albert = _typeSystem.UserInfo.Create(3712, "Albert", null);
            _robert = _typeSystem.UserInfo.Create(12, "Robert", null);
            _time0 = new DateTime(2000, 1, 1, 14, 35, 59, DateTimeKind.Utc);
            _time1 = new DateTime(2001, 2, 2, 14, 35, 59, DateTimeKind.Utc);
            _time2 = new DateTime(2002, 3, 3, 14, 35, 59, DateTimeKind.Utc);
            _time3 = new DateTime(2003, 4, 4, 14, 35, 59, DateTimeKind.Utc);
        }

        [Test]
        public void StdUserInfo_constructor_check_anonymous_constraints()
        {
            Action fail;
            fail = () => new StdUserInfo( 0, "Name for Anonymous" );
            fail.Should().Throw<ArgumentException>();
            fail = () => new StdUserInfo( 3712, "" );
            fail.Should().Throw<ArgumentException>();
        }

        [Test]
        public void StdAuthenticationInfo_expirations_can_easily_be_checked()
        {
            // Challenge Expires only.
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert, null, _time2, null, _time0);
                a.Level.Should().Be(AuthLevel.Normal);
                a.User.UserId.Should().Be(_albert.UserId);
                a.CriticalExpires.Should().BeNull();

                var aNotExpired = a.CheckExpiration(_time1);
                aNotExpired.Should().BeSameAs(a);

                var aExpired = a.CheckExpiration(_time2);
                aExpired.Level.Should().Be(AuthLevel.Unsafe);
                aExpired.User.UserId.Should().Be(0);
                aExpired.UnsafeUser.UserId.Should().Be(_albert.UserId);

                aExpired = a.CheckExpiration(_time3);
                aExpired.Level.Should().Be(AuthLevel.Unsafe);
                aExpired.User.UserId.Should().Be(0);
                aExpired.UnsafeUser.UserId.Should().Be(_albert.UserId);
            }
            // Challenge CriticalExpires.
            {
                var a = new StdAuthenticationInfo(_typeSystem, _albert, null, _time2, _time1, _time0);
                a.Level.Should().Be(AuthLevel.Critical);

                var noChange = a.CheckExpiration(_time0);
                noChange.Should().BeSameAs(a);

                var toNormal = a.CheckExpiration(_time1);
                toNormal.Level.Should().Be(AuthLevel.Normal);

                var toUnsafe = a.CheckExpiration(_time2);
                toUnsafe.Level.Should().Be(AuthLevel.Unsafe);
                toUnsafe = a.CheckExpiration(_time3);
                toUnsafe.Level.Should().Be(AuthLevel.Unsafe);
            }
        }

        [Test]
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

        [Test]
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

        [Test]
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

        [Test]
        public void setting_a_valid_CriticalExpires_boosts_the_Expires()
        {
            var a = new StdAuthenticationInfo(_typeSystem, _albert);
            a.Level.Should().Be(AuthLevel.Unsafe);
            a = a.SetCriticalExpires(_time1, _time0);
            a.Level.Should().Be(AuthLevel.Critical);
            a.CriticalExpires.Should().Be(_time1);
            a.Expires.Should().Be(_time1);

            a = a.SetCriticalExpires(_time2, _time1);
            a.Level.Should().Be(AuthLevel.Critical);
            a.CriticalExpires.Should().Be(_time2);
            a.Expires.Should().Be(_time2);
        }

        [Test]
        public void setting_an_expired_CriticalExpires_does_not_change_the_Expires_iif_it_is_still_valid()
        {
            var a = new StdAuthenticationInfo(_typeSystem, _albert);
            a.Level.Should().Be(AuthLevel.Unsafe);
            a = a.SetExpires(_time3, _time2);
            a.Level.Should().Be(AuthLevel.Normal);
            a.Expires.Should().Be(_time3);
            a.CriticalExpires.Should().Be(null);

            a = a.SetCriticalExpires(_time1, _time2);
            a.Level.Should().Be(AuthLevel.Normal);
            a.CriticalExpires.Should().Be(null);
            a.Expires.Should().Be(_time3, "it has not changed.");

            a = a.SetCriticalExpires(_time1, _time3);
            a.Level.Should().Be(AuthLevel.Unsafe);
            a.Expires.Should().Be(null);
            a.CriticalExpires.Should().Be(null);
        }

        [Test]
        public void setting_Expires_impacts_CriticalExpires()
        {
            // Albert's Critical expiration is time2 and its expiration is time3.
            var a = new StdAuthenticationInfo(_typeSystem, _albert, null, _time3, _time2, _time0);
            a.Level.Should().Be(AuthLevel.Critical);
            a.CriticalExpires.Should().Be(_time2);

            var aSetExpiresLonger = a.SetExpires(_time3.AddDays(1), _time0);
            aSetExpiresLonger.Level.Should().Be(AuthLevel.Critical);
            aSetExpiresLonger.CriticalExpires.Should().Be(_time2, "CriticalExpires has not changed.");
            aSetExpiresLonger.Expires.Should().Be(_time3.AddDays(1));

            var aSetExpiresShorter = a.SetExpires(_time1, _time0);
            aSetExpiresShorter.Level.Should().Be(AuthLevel.Critical);
            aSetExpiresShorter.CriticalExpires.Should().Be(_time1, "CriticalExpires is never greater than Expires.");
            aSetExpiresShorter.Expires.Should().Be(_time1);

            var aSetExpiresAfterCriticalSameExpires = a.SetExpires(_time3, _time2);
            aSetExpiresAfterCriticalSameExpires.Level.Should().Be(AuthLevel.Normal);
            aSetExpiresAfterCriticalSameExpires.Expires.Should().Be(_time3);
            aSetExpiresAfterCriticalSameExpires.CriticalExpires.Should().Be(null);

            var aSetExpiresAfterCritical = a.SetExpires(_time3.AddSeconds(-1), _time2);
            aSetExpiresAfterCritical.Level.Should().Be(AuthLevel.Normal);
            aSetExpiresAfterCritical.Expires.Should().Be(_time3.AddSeconds(-1));
            aSetExpiresAfterCritical.CriticalExpires.Should().Be(null);
        }

        [Test]
        public void clearing_impersonation_automatically_updates_the_expirations()
        {
            // Albert is impersonated in Robert and its Critical expiration time is time1
            // and its expiration is time2.
            var a = new StdAuthenticationInfo(_typeSystem, _albert, _robert, _time2, _time1, _time0);

            var aClearedBefore = a.ClearImpersonation(_time0);
            aClearedBefore.IsImpersonated.Should().BeFalse();
            aClearedBefore.Level.Should().Be(AuthLevel.Critical);

            var aClearedAfterCriticalExpired = a.ClearImpersonation(_time1);
            aClearedAfterCriticalExpired.IsImpersonated.Should().BeFalse();
            aClearedAfterCriticalExpired.Level.Should().Be(AuthLevel.Normal);

            var aClearedLater = a.ClearImpersonation(_time3);
            aClearedLater.IsImpersonated.Should().BeFalse();
            aClearedLater.Level.Should().Be(AuthLevel.Unsafe);
        }


        [Test]
        public void setting_impersonation_automatically_updates_the_expirations()
        {
            // Albert's Critical expiration is time1 and its expiration is time2.
            var a = new StdAuthenticationInfo(_typeSystem, _albert, null, _time2, _time1, _time0);

            var aSetBefore = a.Impersonate( _robert, _time0);
            aSetBefore.IsImpersonated.Should().BeTrue();
            aSetBefore.User.Should().BeSameAs(_robert);
            aSetBefore.ActualUser.Should().BeSameAs(_albert);
            aSetBefore.Level.Should().Be(AuthLevel.Critical);

            var aSetAfterCriticalExpired = a.Impersonate( _robert, _time1);
            aSetAfterCriticalExpired.IsImpersonated.Should().BeTrue();
            aSetAfterCriticalExpired.Level.Should().Be(AuthLevel.Normal);

            var aSetLater = a.Impersonate(_robert,_time3);
            aSetLater.IsImpersonated.Should().BeTrue();
            aSetLater.Level.Should().Be(AuthLevel.Unsafe);
        }

        [Test]
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
