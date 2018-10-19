using System;
using System.Diagnostics;

namespace CK.Auth
{
    /// <summary>
    /// Default concrete implementation of <see cref="StdAuthenticationInfo{TUserInfo}"/>.
    /// </summary>
    public sealed class StdAuthenticationInfo<TUserInfo> : StdAuthenticationInfo<TUserInfo,StdAuthenticationInfo<TUserInfo>>
        where TUserInfo : StdUserInfo
    {
        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo{TUserInfo}"/> with a specific "current" date and time.
        /// This constructor is the one that must be ultimately called by any specialization.
        /// It may be used directly in specific scenario (unit testing is one of them).
        /// </summary>
        /// <param name="userInfoType">The user info type system. Must not be null.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <paramref name="utcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after <paramref name="utcNow"/> in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
        /// <param name="utcNow">The "current" date and time.</param>
        public StdAuthenticationInfo(
            StdUserInfoType<TUserInfo> userInfoType,
            TUserInfo actualUser,
            TUserInfo user,
            DateTime? expires,
            DateTime? criticalExpires,
            DateTime utcNow )
            : base( userInfoType, actualUser, user, expires, criticalExpires, utcNow )
        {
        }

        /// <summary>
        /// Extension point required to handle specialization of this class.
        /// Methods like <see cref="Impersonate"/> or <see cref="SetExpires"/> call 
        /// this instead of StdAuthenticationInfo constructor to allow specializations to 
        /// handle extra fields and return the actual specialized type.
        /// </summary>
        /// <param name="actualUser">The new actual user.</param>
        /// <param name="user">The new user.</param>
        /// <param name="expires">The new expires time.</param>
        /// <param name="criticalExpires">The new critical expires time.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>New authentication info.</returns>
        protected override StdAuthenticationInfo<TUserInfo> Clone( TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
        {
            return new StdAuthenticationInfo<TUserInfo>( UserInfoType, actualUser, user, expires, criticalExpires, utcNow );
        }

    }
}
