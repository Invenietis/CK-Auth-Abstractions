using System;

namespace CK.Auth
{
    /// <summary>
    /// Primary contract for authentication: an authentication information handles
    /// authentication level, impersonation and expiration date.
    /// This interface has been designed so that using <see cref="AuthLevel.Unsafe"/> requires
    /// an explicit use of <see cref="UnsafeUser"/> or <see cref="UnsafeActualUser"/>.
    /// </summary>
    public interface IAuthenticationInfo<TUserInfo> : IAuthenticationInfo where TUserInfo : IUserInfo
    {
        /// <summary>
        /// Gets the user information itself when <see cref="Level"/> is <see cref="AuthLevel.Normal"/> 
        /// or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this User property 
        /// is the anonymous.)
        /// </summary>
        new TUserInfo User { get; }

        /// <summary>
        /// Gets the actual user identifier that has been authenticate when <see cref="Level"/> is 
        /// <see cref="AuthLevel.Normal"/> or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this actual user 
        /// property is the anonymous.)
        /// </summary>
        new TUserInfo ActualUser { get; }

        /// <summary>
        /// Gets the user information itself whatever <see cref="Level"/> is.
        /// </summary>
        new TUserInfo UnsafeUser { get; }

        /// <summary>
        /// Gets the actual user identifier that has been authenticated whatever <see cref="Level"/> is.
        /// This enables the impersonation to be effective when the authentication expired so that
        /// an impersonated administrator/tester can continue to challenge a system in this case.
        /// </summary>
        new TUserInfo UnsafeActualUser { get; }

        /// <summary>
        /// Impersonates this <see cref="ActualUser"/>: the <see cref="User"/> will be the new one.
        /// Calling this on the anonymous MUST throw an <see cref="InvalidOperationException"/>.
        /// </summary>
        /// <param name="user">The new impersonated user.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>This or a new new authentication info object.</returns>
        IAuthenticationInfo<TUserInfo> Impersonate( TUserInfo user, DateTime utcNow );

    }
}
