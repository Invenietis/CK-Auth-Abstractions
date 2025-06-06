using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.Auth;

/// <summary>
/// Extends contracts and objects fom this package.
/// </summary>
public static class AuthenticationExtensions
{
    /// <summary>
    /// Handles expiration checks by returning an updated information whenever <see cref="IAuthenticationInfo.Expires"/>
    /// or <see cref="IAuthenticationInfo.CriticalExpires"/> are greater than <see cref="DateTime.UtcNow"/>.
    /// </summary>
    /// <returns>This or an updated authentication information.</returns>
    public static IAuthenticationInfo CheckExpiration( this IAuthenticationInfo @this ) => @this.CheckExpiration( DateTime.UtcNow );

    /// <summary>
    /// Returns a new authentication information with <see cref="IAuthenticationInfo.Expires"/> sets
    /// to the new value (or this authentication info if it is the same).
    /// </summary>
    /// <param name="this">This authentication info.</param>
    /// <param name="expires">The new Expires value.</param>
    /// <returns>The updated authentication info.</returns>
    public static IAuthenticationInfo SetExpires( this IAuthenticationInfo @this, DateTime? expires ) => @this.SetExpires( expires, DateTime.UtcNow );

    /// <summary>
    /// Returns a new authentication information with <see cref="IAuthenticationInfo.CriticalExpires"/> sets
    /// to the new value (or this authentication info if it is the same).
    /// If the new <paramref name="criticalExpires"/> is greater than <see cref="IAuthenticationInfo.Expires"/>,
    /// the new Expires is automatically boosted to the new critical expires time. 
    /// </summary>
    /// <param name="this">This authentication info.</param>
    /// <param name="criticalExpires">The new CriticalExpires value.</param>
    /// <returns>The updated authentication info.</returns>
    public static IAuthenticationInfo SetCriticalExpires( this IAuthenticationInfo @this, DateTime? criticalExpires ) => @this.SetCriticalExpires( criticalExpires, DateTime.UtcNow );

    /// <summary>
    /// Sets a device identifier.
    /// The empty string is valid and denotes the absence of a specific device identifier.
    /// <para>
    /// Recall that a device identifier is not trustable in any way. Any information that may be sent to a user via
    /// a device should actually be be sent to a couple (DeviceId, UserId) and the UserId should be eventually challenged
    /// to avoid any kind of phishing.
    /// </para>
    /// </summary>
    /// <param name="this">This authentication info.</param>
    /// <param name="deviceId">The new device identifier.</param>
    /// <returns>The updated authentication info.</returns>
    public static IAuthenticationInfo SetDeviceId( this IAuthenticationInfo @this, string deviceId ) => @this.SetDeviceId( deviceId, DateTime.UtcNow );

    /// <summary>
    /// Removes impersonation if any (the <see cref="IAuthenticationInfo.ActualUser"/> 
    /// becomes the <see cref="IAuthenticationInfo.User"/>).
    /// </summary>
    /// <param name="this">This authentication info.</param>
    /// <returns>This or a new authentication info object.</returns>
    public static IAuthenticationInfo ClearImpersonation( this IAuthenticationInfo @this ) => @this.ClearImpersonation( DateTime.UtcNow );

    /// <summary>
    /// Impersonates this <see cref="IAuthenticationInfo.ActualUser"/>: the <see cref="IAuthenticationInfo.User"/> will 
    /// be the new one.
    /// Calling this if ActualUser is the anonymous MUST throw an <see cref="InvalidOperationException"/>.
    /// </summary>
    /// <param name="this">This authentication info.</param>
    /// <param name="user">The new impersonated user.</param>
    /// <returns>This or a new new authentication info object.</returns>
    public static IAuthenticationInfo Impersonate( this IAuthenticationInfo @this, IUserInfo user ) => @this.Impersonate( user, DateTime.UtcNow );

}
