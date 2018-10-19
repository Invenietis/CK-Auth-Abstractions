using System;
using System.Diagnostics;

namespace CK.Auth
{

    /// <summary>
    /// Concrete immutable implementation of <see cref="IAuthenticationInfo{StdUserInfo}"/>.
    /// This class is sealed. Specialized authentication info type must be created by
    /// specializing <see cref="StdAuthenticationInfo{TUserInfo, TThis}"/>.
    /// </summary>
    public sealed class StdAuthenticationInfo : StdAuthenticationInfo<StdUserInfo, StdAuthenticationInfo>
    {
        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/>.
        /// </summary>
        /// <param name="userInfoType">The user type system. Must not be null.</param>
        /// <param name="user">The user (and actual user). Can be null.</param>
        /// <param name="expires">Expiration of authentication.</param>
        /// <param name="criticalExpires">Expiration of critical authentication.</param>
        public StdAuthenticationInfo(
            StdUserInfoType<StdUserInfo> userInfoType,
            StdUserInfo user,
            DateTime? expires = null,
            DateTime? criticalExpires = null )
            : this( userInfoType, user, null, expires, criticalExpires, DateTime.UtcNow )
        {
        }

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/> with all its possible data.
        /// </summary>
        /// <param name="userInfoType">The user type system. Must not be null.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <see cref="DateTime.UtcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after DateTime.UtcNow in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
        public StdAuthenticationInfo(
            StdUserInfoType<StdUserInfo> userInfoType,
            StdUserInfo actualUser,
            StdUserInfo user,
            DateTime? expires,
            DateTime? criticalExpires )
            : this( userInfoType, actualUser, user, expires, criticalExpires, DateTime.UtcNow )
        {
        }

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/> with a specific "current" date and time.
        /// This constructor is the one that must be ultimately called by any specialization.
        /// It may be used directly in specific scenario (unit testing is one of them), and derived
        /// classes must call this constructor.
        /// </summary>
        /// <param name="userInfoType">The user info type system. Must not be null.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <paramref name="utcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after <paramref name="utcNow"/> in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
        /// <param name="utcNow">The "current" date and time.</param>
        public StdAuthenticationInfo(
            StdUserInfoType<StdUserInfo> userInfoType,
            StdUserInfo actualUser,
            StdUserInfo user,
            DateTime? expires,
            DateTime? criticalExpires,
            DateTime utcNow )
            : base( userInfoType, actualUser, user, expires, criticalExpires, utcNow )
        {
        }

        /// <summary>
        /// Returns a new <see cref="StdAuthenticationInfo"/>.
        /// </summary>
        /// <param name="actualUser">The new actual user.</param>
        /// <param name="user">The new user.</param>
        /// <param name="expires">The new expires time.</param>
        /// <param name="criticalExpires">The new critical expires time.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>New authentication info.</returns>
        protected override StdAuthenticationInfo Clone( StdUserInfo actualUser, StdUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
        {
            return new StdAuthenticationInfo( UserInfoType, actualUser, user, expires, criticalExpires, utcNow );
        }
    }
}
