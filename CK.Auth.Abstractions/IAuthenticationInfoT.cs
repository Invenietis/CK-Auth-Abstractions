using System;

namespace CK.Auth
{
    /// <summary>
    /// Strongly typed primary contract for authentication: an authentication information handles
    /// authentication level, impersonation and expiration date.
    /// This interface has been designed so that using <see cref="AuthLevel.Unsafe"/> requires
    /// an explicit use of <see cref="UnsafeUser"/> or <see cref="UnsafeActualUser"/>.
    /// </summary>
    public interface IAuthenticationInfo<T> : IAuthenticationInfo where T : IUserInfo
    {
        /// <summary>
        /// Gets the user information itself when <see cref="IAuthenticationInfo.Level">Level</see> is <see cref="AuthLevel.Normal"/> 
        /// or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this User property 
        /// is the anonymous.)
        /// </summary>
        new T User { get; }

        /// <summary>
        /// Gets the actual user identifier that has been authenticate when <see cref="IAuthenticationInfo.Level">Level</see> is 
        /// <see cref="AuthLevel.Normal"/> or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this actual user 
        /// property is the anonymous.)
        /// </summary>
        new T ActualUser { get; }

        /// <summary>
        /// Gets the user information itself whatever <see cref="IAuthenticationInfo.Level">Level</see> is.
        /// </summary>
        new T UnsafeUser { get; }

        /// <summary>
        /// Gets the actual user identifier that has been authenticate whatever <see cref="IAuthenticationInfo.Level">Level</see> is.
        /// </summary>
        new T UnsafeActualUser { get; }

        /// <summary>
        /// Handles expiration checks by returning an updated information whenever <see cref="IAuthenticationInfo.Expires">Expires</see>
        /// or <see cref="IAuthenticationInfo.CriticalExpires">CriticalExpires</see> are greater than <paramref name="utcNow"/>.
        /// </summary>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>This or an updated authentication information.</returns>
        new IAuthenticationInfo<T> CheckExpiration(DateTime utcNow);

        /// <summary>
        /// Removes impersonation if any (the <see cref="ActualUser"/> becomes the <see cref="User"/>).
        /// </summary>
        /// <returns>This or a new authentication info object.</returns>
        new IAuthenticationInfo<T> ClearImpersonation();

        /// <summary>
        /// Impersonates this <see cref="ActualUser"/>: the <see cref="User"/> will be the new one.
        /// Calling this on the anonymous MUST throw an <see cref="InvalidOperationException"/>.
        /// </summary>
        /// <param name="user">The new impersonated user.</param>
        /// <returns>This or a new new authentication info object.</returns>
        new IAuthenticationInfo<T> Impersonate( IUserInfo user );

    }
}
