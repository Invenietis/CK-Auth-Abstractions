using CK.Core;
using System;

namespace CK.Auth;

/// <summary>
/// Primary contract for authentication: an authentication information handles
/// authentication level, impersonation and expiration date.
/// This interface has been designed so that using <see cref="AuthLevel.Unsafe"/> requires
/// an explicit use of <see cref="UnsafeUser"/>.
/// </summary>
public interface IAuthenticationInfo : IAmbientAutoService
{
    /// <summary>
    /// Gets the user information itself when <see cref="Level"/> is <see cref="AuthLevel.Normal"/> 
    /// or <see cref="AuthLevel.Critical"/>.
    /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this User property 
    /// is the anonymous.)
    /// </summary>
    IUserInfo User { get; }

    /// <summary>
    /// Gets the user information itself whatever <see cref="Level"/> is.
    /// </summary>
    IUserInfo UnsafeUser { get; }

    /// <summary>
    /// Gets the actual user identifier that has been authenticated when <see cref="Level"/> is 
    /// <see cref="AuthLevel.Normal"/> or <see cref="AuthLevel.Critical"/>.
    /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this actual user 
    /// property is the anonymous.)
    /// </summary>
    IUserInfo ActualUser { get; }

    /// <summary>
    /// Gets the actual user identifier that has been authenticated whatever <see cref="Level"/> is.
    /// This enables the impersonation to be effective when the authentication expired so that
    /// an impersonated administrator/tester can continue to challenge a system in this case.
    /// </summary>
    IUserInfo UnsafeActualUser { get; }

    /// <summary>
    /// Gets the authentication level of this authentication information.
    /// </summary>
    AuthLevel Level { get; }

    /// <summary>
    /// The expiration time for this authentication.
    /// </summary>
    DateTime? Expires { get; }

    /// <summary>
    /// The expiration time for critical authentication level.
    /// </summary>
    DateTime? CriticalExpires { get; }

    /// <summary>
    /// Gets whether the actual user is actually 
    /// impersonated (<see cref="User"/> is not the same as <see cref="ActualUser"/>).
    /// </summary>
    bool IsImpersonated { get; }

    /// <summary>
    /// Gets the device identifier.
    /// Can be empty: the device is not identified in any way. 
    /// <para>
    /// A device identifier is not trustable in any way. Any information that may be sent to a user via
    /// a device should actually be sent to a couple (DeviceId, UserId) and the UserId should be eventually
    /// challenged to avoid any kind of phishing.
    /// </para>
    /// </summary>
    string DeviceId { get; }

    /// <summary>
    /// Handles expiration checks by returning an updated information whenever <see cref="Expires"/>
    /// or <see cref="CriticalExpires"/> are greater than <paramref name="utcNow"/>.
    /// </summary>
    /// <param name="utcNow">The "current" date and time to challenge.</param>
    /// <returns>This or an updated authentication information.</returns>
    IAuthenticationInfo CheckExpiration( DateTime utcNow );

    /// <summary>
    /// Returns a new authentication information with <see cref="Expires"/> sets
    /// to the new value (or this authentication info if it is the same).
    /// </summary>
    /// <param name="expires">The new <see cref="Expires"/> value.</param>
    /// <param name="utcNow">The "current" date and time to challenge.</param>
    /// <returns>The updated authentication info.</returns>
    IAuthenticationInfo SetExpires( DateTime? expires, DateTime utcNow );

    /// <summary>
    /// Returns a new authentication information with <see cref="CriticalExpires"/> sets
    /// to the new value (or this authentication info if it is the same).
    /// If the new <paramref name="criticalExpires"/> is greater than <see cref="Expires"/>,
    /// the new Expires is automatically boosted to the new critical expires time. 
    /// </summary>
    /// <param name="criticalExpires">The new CriticalExpires value.</param>
    /// <param name="utcNow">The "current" date and time to challenge.</param>
    /// <returns>The updated authentication info.</returns>
    IAuthenticationInfo SetCriticalExpires( DateTime? criticalExpires, DateTime utcNow );

    /// <summary>
    /// Removes impersonation if any (the <see cref="ActualUser"/> becomes the <see cref="User"/>).
    /// </summary>
    /// <param name="utcNow">The "current" date and time to challenge.</param>
    /// <returns>This or a new authentication info object.</returns>
    IAuthenticationInfo ClearImpersonation( DateTime utcNow );

    /// <summary>
    /// Impersonates this <see cref="ActualUser"/>: the <see cref="User"/> will be the new one.
    /// Calling this on the anonymous MUST throw an <see cref="InvalidOperationException"/>.
    /// </summary>
    /// <param name="user">The new impersonated user.</param>
    /// <param name="utcNow">The "current" date and time to challenge.</param>
    /// <returns>This or a new authentication info object.</returns>
    IAuthenticationInfo Impersonate( IUserInfo user, DateTime utcNow );

    /// <summary>
    /// Sets a device identifier.
    /// The empty string is valid and denotes the absence of a specific device identifier.
    /// <para>
    /// Recall that a device identifier is not trustable in any way. Any information that may be sent to a user via
    /// a device should actually be be sent to a couple (DeviceId, UserId) and the UserId should be eventually challenged
    /// to avoid any kind of phishing.
    /// </para>
    /// </summary>
    /// <param name="deviceId">The new device identifier.</param>
    /// <param name="utcNow">The "current" date and time to challenge to update the level.</param>
    /// <returns>This or a new authentication info object.</returns>
    IAuthenticationInfo SetDeviceId( string deviceId, DateTime utcNow );

}
