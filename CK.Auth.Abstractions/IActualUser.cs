using System;

namespace CK.Auth;

/// <summary>
/// Defines the <see cref="IAuthenticationInfo.ActualUser"/> information.
/// (This is not implemented yet.)
/// </summary>
public interface IActualUser
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
    /// Gets the actual authentication level: this is never lower than the <see cref="IAuthenticationInfo.Level"/>.
    /// </summary>
    AuthLevel Level { get; }

}
