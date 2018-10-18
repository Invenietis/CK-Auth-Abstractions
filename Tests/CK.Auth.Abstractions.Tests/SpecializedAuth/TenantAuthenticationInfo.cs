using System;
using System.Collections.Generic;
using System.Text;

namespace CK.Auth.Abstractions.Tests.SpecializedAuth
{
    public class TenantAuthenticationInfo : StdAuthenticationInfo 
    {
        /// <summary>
        /// Initializes a new <see cref="TenantAuthenticationInfo"/> with all its possible data.
        /// </summary>
        /// <param name="typeSystem">The type system. Must not be null.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <see cref="DateTime.UtcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after DateTime.UtcNow in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
        /// <param name="utcNow">The "current" date and time.</param>
        public TenantAuthenticationInfo( IAuthenticationTypeSystem typeSystem, int tenantId, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
            : base( typeSystem, actualUser, user, expires, criticalExpires, utcNow )
        {
            TenantId = tenantId;
        }

        /// <summary>
        /// Gets the tenant identifier.
        /// </summary>
        public int TenantId { get; }

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
        protected override sealed StdAuthenticationInfo Clone( IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
        {
            return new TenantAuthenticationInfo( TypeSystem, TenantId, actualUser, user, expires, criticalExpires, utcNow );
        }

        /// <summary>
        /// Extension point required to handle specialization of this class.
        /// Methods like <see cref="Impersonate"/>, <see cref="SetExpires"/> or <see cref="SetTenatId"/> call 
        /// this instead of TenantAuthenticationInfo constructor to allow specializations to 
        /// handle extra fields and return the actual specialized type.
        /// </summary>
        /// <param name="tenantId">The new tenant identifier.</param>
        /// <param name="actualUser">The new actual user.</param>
        /// <param name="user">The new user.</param>
        /// <param name="expires">The new expires time.</param>
        /// <param name="criticalExpires">The new critical expires time.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>New authentication info.</returns>
        protected virtual StdAuthenticationInfo Clone( int tenantId, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
        {
            return new TenantAuthenticationInfo( TypeSystem, tenantId, actualUser, user, expires, criticalExpires, utcNow );
        }
    }
}
