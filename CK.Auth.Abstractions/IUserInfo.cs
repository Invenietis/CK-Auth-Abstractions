using System.Collections.Generic;

namespace CK.Auth
{
    /// <summary>
    /// Defines the core information of a user.
    /// </summary>
    public interface IUserInfo
    {
        /// <summary>
        /// Gets the user identifier.
        /// There are no constraints on this value (except that 0 is the Anonymous identifier by design).
        /// It may be a negative value.
        /// </summary>
        int UserId { get; }

        /// <summary>
        /// Gets the user name.
        /// It is never null and it is empty if and only if <see cref="UserId"/> is 0.
        /// </summary>
        string UserName { get; }

        /// <summary>
        /// Gets the authentication providers that this user has used at least once.
        /// It is never null but may be empty. 
        /// </summary>
        IReadOnlyList<IUserProviderInfo> Providers { get; }

    }
}
