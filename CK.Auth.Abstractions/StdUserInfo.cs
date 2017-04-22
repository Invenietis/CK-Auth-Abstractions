using System;
using System.Collections.Generic;

namespace CK.Auth
{
    /// <summary>
    /// Standard immutable implementation of <see cref="IUserInfo"/>.
    /// </summary>
    public class StdUserInfo : IUserInfo
    {
        static readonly IUserProviderInfo[] _emptyProviders = new IUserProviderInfo[0];

        /// <summary>
        /// Initializes a new <see cref="StdUserInfo"/>.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="userName">The user name. Can be null or empty if and only if <paramref name="userId"/> is 0.</param>
        /// <param name="providers">The provider list.</param>
        public StdUserInfo( int userId, string userName, IReadOnlyList<IUserProviderInfo> providers = null )
        {
            UserId = userId;
            UserName = userName ?? string.Empty;
            if ((UserName.Length == 0) != (userId == 0)) throw new ArgumentException($"{userName} is empty if and only {userId} is 0.");
            Providers = providers ?? _emptyProviders;
        }

        /// <summary>
        /// See <see cref="IUserInfo.UserId"/>.
        /// </summary>
        public int UserId { get; }

        /// <summary>
        /// See <see cref="IUserInfo.UserName"/>.
        /// </summary>
        public string UserName { get; }

        /// <summary>
        /// See <see cref="IUserInfo.Providers"/>.
        /// </summary>
        public IReadOnlyList<IUserProviderInfo> Providers { get; }

    }
}
