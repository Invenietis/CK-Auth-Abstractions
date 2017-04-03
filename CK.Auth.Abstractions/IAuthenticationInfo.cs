using System;

namespace CK.Auth
{
    /// <summary>
    /// Primary contract for authentication: an authentication information handles
    /// authentication level, impersonation and expiration date.
    /// This interface has been designed so that using <see cref="AuthLevel.Unsafe"/> requires
    /// an explicit use of <see cref="UnsafeUser"/> or <see cref="UnsafeActualUser"/>.
    /// </summary>
    public interface IAuthenticationInfo
    {
        /// <summary>
        /// Gets the user information itself when <see cref="Level"/> is <see cref="AuthLevel.Normal"/> 
        /// or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this User property 
        /// is the anonymous.)
        /// </summary>
        IUserInfo User { get; }

        /// <summary>
        /// Gets the actual user identifier that has been authenticate when <see cref="Level"/> is 
        /// <see cref="AuthLevel.Normal"/> or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this actual user 
        /// property is the anonymous.)
        /// </summary>
        IUserInfo ActualUser { get; }

        /// <summary>
        /// Gets the user information itself whatever <see cref="Level"/> is.
        /// </summary>
        IUserInfo UnsafeUser { get; }

        /// <summary>
        /// Gets the actual user identifier that has been authenticate whatever <see cref="Level"/> is.
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
        /// Handles expiration checks by returning an updated information whenever <see cref="Expires"/>
        /// or <see cref="CriticalExpires"/> are greater than <paramref name="utcNow"/>.
        /// </summary>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>This or an updated authentication information.</returns>
        IAuthenticationInfo CheckExpiration(DateTime utcNow);
    }
}
