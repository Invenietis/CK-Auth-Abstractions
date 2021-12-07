using System;

namespace CK.Auth
{
    /// <summary>
    /// Defines the <see cref="IAuthenticationInfo.Actual"/> information.
    /// (This is not implemented yet.)
    /// </summary>
    public interface IActualAuthentication
    {
        /// <summary>
        /// Gets the actually authenticated user.
        /// </summary>
        IUserInfo User { get; }

        /// <summary>
        /// Gets the actual authentication level: this is never lower than the <see cref="IAuthenticationInfo.Level"/>.
        /// </summary>
        AuthLevel Level { get; }

    }
}
