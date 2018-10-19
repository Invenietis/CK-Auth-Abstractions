using System;
using System.Collections.Generic;
using System.Text;

namespace CK.Auth.Abstractions.Tests.SpecializedAuth
{
    public class TenantAuthenticationInfo<TUserInfo> : StdAuthenticationInfo<TUserInfo, TenantAuthenticationInfo<TUserInfo>>
        where TUserInfo : StdUserInfo
    {
        /// <summary>
        /// Helper with less parameters.
        /// </summary>
        /// <param name="userInfoType">The user type system instance. Must not be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <see cref="DateTime.UtcNow"/> otherwise Level is <see cref="AuthLevel.Unsafe"/>.</param>
        public TenantAuthenticationInfo( StdUserInfoType<TUserInfo> userInfoType, int tenantId, TUserInfo user, DateTime? expires )
            : this( userInfoType, tenantId, null, user, expires, null, DateTime.UtcNow )
        {
        }

        /// <summary>
        /// Initializes a new <see cref="TenantAuthenticationInfo"/> with all its possible data.
        /// </summary>
        /// <param name="userInfoType">The user type system instance. Must not be null.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <paramref name="utcNow"/> otherwise Level is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after DateTime.UtcNow in order for Level to be <see cref="AuthLevel.Critical"/>.</param>
        /// <param name="utcNow">The "current" date and time.</param>
        public TenantAuthenticationInfo( StdUserInfoType<TUserInfo> userInfoType, int tenantId, TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
            : base( userInfoType, actualUser, user, expires, criticalExpires, utcNow )
        {
            TenantId = tenantId;
        }

        /// <summary>
        /// Gets the tenant identifier.
        /// </summary>
        public int TenantId { get; }

        /// <summary>
        /// Sets the <see cref="TenantId"/>.
        /// </summary>
        /// <param name="tenantId">The new tenant identifier.</param>
        /// <returns>A new authentication info ot this one if tenant identifier has not changed.</returns>
        public TenantAuthenticationInfo<TUserInfo> SetTenantId( int tenantId )
        {
            return tenantId != TenantId
                    ? new TenantAuthenticationInfo<TUserInfo>( UserInfoType, tenantId, ActualUser, User, Expires, CriticalExpires, DateTime.UtcNow )
                    : CheckExpiration();
        }

        /// <summary>
        /// Overridden to return a new <see cref="TenantAuthenticationInfo"/> with the same <see cref="TenantId"/>
        /// as this one.
        /// </summary>
        /// <param name="actualUser">The new actual user.</param>
        /// <param name="user">The new user.</param>
        /// <param name="expires">The new expires time.</param>
        /// <param name="criticalExpires">The new critical expires time.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>New tenant aware authentication info.</returns>
        protected override sealed TenantAuthenticationInfo<TUserInfo> Clone( TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
        {
            return new TenantAuthenticationInfo<TUserInfo>( UserInfoType, TenantId, actualUser, user, expires, criticalExpires, utcNow );
        }
    }
}
