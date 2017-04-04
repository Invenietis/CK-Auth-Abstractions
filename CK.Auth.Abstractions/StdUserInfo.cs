using System;
using System.Collections.Generic;

namespace CK.Auth
{
    /// <summary>
    /// Standard immutable implementation of <see cref="IUserInfo"/>.
    /// </summary>
    public class StdUserInfo : IUserInfo
    {
        /// <summary>
        /// Initializes a new <see cref="StdUserInfo"/>.
        /// </summary>
        /// <param name="actorId">The actor identifier.</param>
        /// <param name="displayName">The display name. Can be null or empty if and only if <paramref name="actorId"/> is 0.</param>
        /// <param name="providers">The provider list.</param>
        public StdUserInfo( int actorId, string displayName, IReadOnlyList<IUserProviderInfo> providers = null )
        {
            ActorId = actorId;
            DisplayName = displayName ?? string.Empty;
            if ((DisplayName.Length == 0) != (actorId == 0)) throw new ArgumentException($"{displayName} is empty if and only {actorId} is 0.");
            Providers = providers ?? Array.Empty<IUserProviderInfo>();
        }

        /// <summary>
        /// See <see cref="IUserInfo.ActorId"/>.
        /// </summary>
        public int ActorId { get; }

        /// <summary>
        /// See <see cref="IUserInfo.DisplayName"/>.
        /// </summary>
        public string DisplayName { get; }

        /// <summary>
        /// See <see cref="IUserInfo.Providers"/>.
        /// </summary>
        public IReadOnlyList<IUserProviderInfo> Providers { get; }

    }
}
