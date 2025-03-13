using Shouldly;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Claims;
using NUnit.Framework;
using CK.Core;

namespace CK.Auth.Abstractions.Tests;

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
        _albert = _typeSystem.UserInfo.Create( 3712, "Albert", null );
        _robert = _typeSystem.UserInfo.Create( 12, "Robert", null );
        _time0 = new DateTime( 2000, 1, 1, 14, 35, 59, DateTimeKind.Utc );
        _time1 = new DateTime( 2001, 2, 2, 14, 35, 59, DateTimeKind.Utc );
        _time2 = new DateTime( 2002, 3, 3, 14, 35, 59, DateTimeKind.Utc );
        _time3 = new DateTime( 2003, 4, 4, 14, 35, 59, DateTimeKind.Utc );
    }

    [Test]
    public void StdUserInfo_constructor_check_anonymous_constraints()
    {
        Util.Invokable( () => new StdUserInfo( 0, "Name for Anonymous" ) )?.ShouldThrow<ArgumentException>();
        Util.Invokable( () => new StdUserInfo( 3712, "" ) ).ShouldThrow<ArgumentException>();
    }

    [Test]
    public void StdAuthenticationInfo_expirations_can_easily_be_checked()
    {
        // Challenge Expires only.
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert, null, _time2, null, "device", _time0 );
            a.Level.ShouldBe( AuthLevel.Normal );
            a.User.UserId.ShouldBe( _albert.UserId );
            a.CriticalExpires.ShouldBeNull();

            var aNotExpired = a.CheckExpiration( _time1 );
            aNotExpired.ShouldBeSameAs( a );

            var aExpired = a.CheckExpiration( _time2 );
            aExpired.Level.ShouldBe( AuthLevel.Unsafe );
            aExpired.User.UserId.ShouldBe( 0 );
            aExpired.UnsafeUser.UserId.ShouldBe( _albert.UserId );

            aExpired = a.CheckExpiration( _time3 );
            aExpired.Level.ShouldBe( AuthLevel.Unsafe );
            aExpired.User.UserId.ShouldBe( 0 );
            aExpired.UnsafeUser.UserId.ShouldBe( _albert.UserId );
        }
        // Challenge CriticalExpires.
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert, null, _time2, _time1, "device", _time0 );
            a.Level.ShouldBe( AuthLevel.Critical );

            var noChange = a.CheckExpiration( _time0 );
            noChange.ShouldBeSameAs( a );

            var toNormal = a.CheckExpiration( _time1 );
            toNormal.Level.ShouldBe( AuthLevel.Normal );

            var toUnsafe = a.CheckExpiration( _time2 );
            toUnsafe.Level.ShouldBe( AuthLevel.Unsafe );
            toUnsafe = a.CheckExpiration( _time3 );
            toUnsafe.Level.ShouldBe( AuthLevel.Unsafe );
        }
    }

    [Test]
    public void Unsafe_level_constructor_for_IAuthenticationInfo()
    {
        var a = new StdAuthenticationInfo( _typeSystem, _albert );
        a.Level.ShouldBe( AuthLevel.Unsafe );
        a.User.ShouldBeSameAs( _typeSystem.UserInfo.Anonymous );
        a.ActualUser.ShouldBeSameAs( _typeSystem.UserInfo.Anonymous );
        a.UnsafeUser.ShouldBeSameAs( _albert );
        a.UnsafeActualUser.ShouldBeSameAs( _albert );
        a.IsImpersonated.ShouldBe( false );
        a.DeviceId.ShouldBeEmpty();
    }

    [Test]
    public void Normal_level_constructor_for_IAuthenticationInfo()
    {
        {
            var time = DateTime.UtcNow.AddDays( 1 );
            var a = new StdAuthenticationInfo( _typeSystem, _albert, time );
            a.Level.ShouldBe( AuthLevel.Normal );
            a.User.ShouldBeSameAs( _albert );
            a.ActualUser.ShouldBeSameAs( _albert );
            a.UnsafeUser.ShouldBeSameAs( _albert );
            a.UnsafeActualUser.ShouldBeSameAs( _albert );
            a.IsImpersonated.ShouldBe( false );
        }
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert, DateTime.UtcNow );
            a.Level.ShouldBe( AuthLevel.Unsafe );
            a.User.ShouldBeSameAs( _typeSystem.UserInfo.Anonymous );
            a.ActualUser.ShouldBeSameAs( _typeSystem.UserInfo.Anonymous );
            a.UnsafeUser.ShouldBeSameAs( _albert );
            a.UnsafeActualUser.ShouldBeSameAs( _albert );
            a.IsImpersonated.ShouldBe( false );
        }
    }

    [Test]
    public void Critical_level_constructor_for_IAuthenticationInfo()
    {
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert,
                            DateTime.UtcNow.AddDays( 1 ),
                            DateTime.UtcNow.AddDays( 2 ) );
            a.Level.ShouldBe( AuthLevel.Critical );
            a.User.ShouldBeSameAs( _albert );
            a.ActualUser.ShouldBeSameAs( _albert );
            a.UnsafeUser.ShouldBeSameAs( _albert );
            a.UnsafeActualUser.ShouldBeSameAs( _albert );
            a.IsImpersonated.ShouldBe( false );
        }
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert,
                            DateTime.UtcNow.AddDays( 1 ),
                            DateTime.UtcNow.AddDays( -1 ) );
            a.Level.ShouldBe( AuthLevel.Normal );
            a.User.ShouldBeSameAs( _albert );
            a.ActualUser.ShouldBeSameAs( _albert );
            a.UnsafeUser.ShouldBeSameAs( _albert );
            a.UnsafeActualUser.ShouldBeSameAs( _albert );
            a.IsImpersonated.ShouldBe( false );
        }
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert,
                            DateTime.UtcNow,
                            DateTime.UtcNow.AddDays( -1 ) );
            a.Level.ShouldBe( AuthLevel.Unsafe );
            a.User.ShouldBeSameAs( _typeSystem.UserInfo.Anonymous );
            a.ActualUser.ShouldBeSameAs( _typeSystem.UserInfo.Anonymous );
            a.UnsafeUser.ShouldBeSameAs( _albert );
            a.UnsafeActualUser.ShouldBeSameAs( _albert );
            a.IsImpersonated.ShouldBe( false );
        }
    }

    [Test]
    public void setting_a_valid_CriticalExpires_boosts_the_Expires()
    {
        var a = new StdAuthenticationInfo( _typeSystem, _albert );
        a.Level.ShouldBe( AuthLevel.Unsafe );
        a = a.SetCriticalExpires( _time1, _time0 );
        a.Level.ShouldBe( AuthLevel.Critical );
        a.CriticalExpires.ShouldBe( _time1 );
        a.Expires.ShouldBe( _time1 );

        a = a.SetCriticalExpires( _time2, _time1 );
        a.Level.ShouldBe( AuthLevel.Critical );
        a.CriticalExpires.ShouldBe( _time2 );
        a.Expires.ShouldBe( _time2 );
    }

    [Test]
    public void setting_an_expired_CriticalExpires_does_not_change_the_Expires_iif_it_is_still_valid()
    {
        var a = new StdAuthenticationInfo( _typeSystem, _albert );
        a.Level.ShouldBe( AuthLevel.Unsafe );
        a = a.SetExpires( _time3, _time2 );
        a.Level.ShouldBe( AuthLevel.Normal );
        a.Expires.ShouldBe( _time3 );
        a.CriticalExpires.ShouldBeNull();

        a = a.SetCriticalExpires( _time1, _time2 );
        a.Level.ShouldBe( AuthLevel.Normal );
        a.CriticalExpires.ShouldBeNull();
        a.Expires.ShouldBe( _time3, "it has not changed." );

        a = a.SetCriticalExpires( _time1, _time3 );
        a.Level.ShouldBe( AuthLevel.Unsafe );
        a.Expires.ShouldBeNull();
        a.CriticalExpires.ShouldBeNull();
    }

    [Test]
    public void setting_Expires_impacts_CriticalExpires()
    {
        // Albert's Critical expiration is time2 and its expiration is time3.
        var a = new StdAuthenticationInfo( _typeSystem, _albert, null, _time3, _time2, "device", _time0 );
        a.Level.ShouldBe( AuthLevel.Critical );
        a.CriticalExpires.ShouldBe( _time2 );

        var aSetExpiresLonger = a.SetExpires( _time3.AddDays( 1 ), _time0 );
        aSetExpiresLonger.Level.ShouldBe( AuthLevel.Critical );
        aSetExpiresLonger.CriticalExpires.ShouldBe( _time2, "CriticalExpires has not changed." );
        aSetExpiresLonger.Expires.ShouldBe( _time3.AddDays( 1 ) );

        var aSetExpiresShorter = a.SetExpires( _time1, _time0 );
        aSetExpiresShorter.Level.ShouldBe( AuthLevel.Critical );
        aSetExpiresShorter.CriticalExpires.ShouldBe( _time1, "CriticalExpires is never greater than Expires." );
        aSetExpiresShorter.Expires.ShouldBe( _time1 );

        var aSetExpiresAfterCriticalSameExpires = a.SetExpires( _time3, _time2 );
        aSetExpiresAfterCriticalSameExpires.Level.ShouldBe( AuthLevel.Normal );
        aSetExpiresAfterCriticalSameExpires.Expires.ShouldBe( _time3 );
        aSetExpiresAfterCriticalSameExpires.CriticalExpires.ShouldBeNull();

        var aSetExpiresAfterCritical = a.SetExpires( _time3.AddSeconds( -1 ), _time2 );
        aSetExpiresAfterCritical.Level.ShouldBe( AuthLevel.Normal );
        aSetExpiresAfterCritical.Expires.ShouldBe( _time3.AddSeconds( -1 ) );
        aSetExpiresAfterCritical.CriticalExpires.ShouldBeNull();
    }

    [Test]
    public void clearing_impersonation_automatically_updates_the_expirations()
    {
        // Albert is impersonated in Robert and its Critical expiration time is time1
        // and its expiration is time2.
        var a = new StdAuthenticationInfo( _typeSystem, _albert, _robert, _time2, _time1, "device", _time0 );

        var aClearedBefore = a.ClearImpersonation( _time0 );
        aClearedBefore.IsImpersonated.ShouldBeFalse();
        aClearedBefore.Level.ShouldBe( AuthLevel.Critical );

        var aClearedAfterCriticalExpired = a.ClearImpersonation( _time1 );
        aClearedAfterCriticalExpired.IsImpersonated.ShouldBeFalse();
        aClearedAfterCriticalExpired.Level.ShouldBe( AuthLevel.Normal );

        var aClearedLater = a.ClearImpersonation( _time3 );
        aClearedLater.IsImpersonated.ShouldBeFalse();
        aClearedLater.Level.ShouldBe( AuthLevel.Unsafe );
    }


    [Test]
    public void setting_impersonation_automatically_updates_the_expirations()
    {
        // Albert's Critical expiration is time1 and its expiration is time2.
        var a = new StdAuthenticationInfo( _typeSystem, _albert, null, _time2, _time1, "device", _time0 );

        var aSetBefore = a.Impersonate( _robert, _time0 );
        aSetBefore.IsImpersonated.ShouldBeTrue();
        aSetBefore.User.ShouldBeSameAs( _robert );
        aSetBefore.ActualUser.ShouldBeSameAs( _albert );
        aSetBefore.Level.ShouldBe( AuthLevel.Critical );

        var aSetAfterCriticalExpired = a.Impersonate( _robert, _time1 );
        aSetAfterCriticalExpired.IsImpersonated.ShouldBeTrue();
        aSetAfterCriticalExpired.Level.ShouldBe( AuthLevel.Normal );

        var aSetLater = a.Impersonate( _robert, _time3 );
        aSetLater.IsImpersonated.ShouldBeTrue();
        aSetLater.Level.ShouldBe( AuthLevel.Unsafe );
    }

    [Test]
    public void impersonation_works_the_same_for_all_levels_except_none()
    {
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert );
            a.Level.ShouldBe( AuthLevel.Unsafe );
            a.IsImpersonated.ShouldBe( false );

            var imp = a.Impersonate( _robert );
            imp.IsImpersonated.ShouldBe( true );
            imp.UnsafeActualUser.ShouldBeSameAs( _albert );
            imp.UnsafeUser.ShouldBeSameAs( _robert );

            var back = imp.ClearImpersonation();
            back.IsImpersonated.ShouldBe( false );
            back.UnsafeActualUser.ShouldBeSameAs( _albert );
            back.UnsafeUser.ShouldBeSameAs( _albert );
        }
        {
            var a = new StdAuthenticationInfo( _typeSystem, _albert, DateTime.UtcNow.AddDays( 1 ) );
            a.Level.ShouldBe( AuthLevel.Normal );
            a.IsImpersonated.ShouldBe( false );

            var imp = a.Impersonate( _robert );
            imp.IsImpersonated.ShouldBe( true );
            imp.ActualUser.ShouldBeSameAs( _albert );
            imp.User.ShouldBeSameAs( _robert );
            imp.UnsafeActualUser.ShouldBeSameAs( _albert );
            imp.UnsafeUser.ShouldBeSameAs( _robert );

            var back = imp.ClearImpersonation();
            back.IsImpersonated.ShouldBe( false );
            back.ActualUser.ShouldBeSameAs( _albert );
            back.User.ShouldBeSameAs( _albert );
            back.UnsafeActualUser.ShouldBeSameAs( _albert );
            back.UnsafeUser.ShouldBeSameAs( _albert );
        }
    }


}
