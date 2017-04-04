using System.Collections.Generic;

namespace CK.Auth
{
    /// <summary>
    /// Defines the core information of a user.
    /// </summary>
    public interface IUserInfo
    {
        /// <summary>
        /// Gets the actor identifier.
        /// There are no constraints on this value (except that 0 is the Anonymous identifier by design).
        /// It may be a negative value.
        /// </summary>
        int ActorId { get; }

        /// <summary>
        /// Gets the user name.
        /// It is never null and it is empty if and only if <see cref="ActorId"/> is 0.
        /// </summary>
        string DisplayName { get; }

        /// <summary>
        /// Gets the authentication providers that this user has used at least once.
        /// It is never null but may be empty. 
        /// </summary>
        IReadOnlyList<IUserProviderInfo> Providers { get; }

    }
}
