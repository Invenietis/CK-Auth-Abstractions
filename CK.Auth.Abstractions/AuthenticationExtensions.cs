using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.Auth
{
    /// <summary>
    /// Extends contracts and objects fom this package.
    /// </summary>
    public static class AuthenticationExtensions
    {
        /// <summary>
        /// Tests a potential null or <see cref="AuthLevel.None"/> level: they are semantically
        /// equivalent. All authentication information with a None level are equivalent.
        /// </summary>
        /// <param name="this">This authentication info.</param>
        /// <returns>True if this authentication info is null or has a None level.</returns>
        public static bool IsNullOrNone( this IAuthenticationInfo @this ) => @this == null || @this.Level == AuthLevel.None;

        /// <summary>
        /// Handles expiration checks by returning an updated information whenever <see cref="IAuthenticationInfo.Expires"/>
        /// or <see cref="IAuthenticationInfo.CriticalExpires"/> are greater than <see cref="DateTime.UtcNow"/>.
        /// </summary>
        /// <returns>This or an updated authentication information.</returns>
        public static IAuthenticationInfo CheckExpiration( this IAuthenticationInfo @this ) => @this.CheckExpiration( DateTime.UtcNow );

        /// <summary>
        /// Returns a new authentication information with <see cref="IAuthenticationInfo.Expires"/> sets
        /// to the new value (or this authentication info if it is the same).
        /// </summary>
        /// <param name="this">This authentication info.</param>
        /// <param name="expires">The new Expires value.</param>
        /// <returns>The updated authentication info.</returns>
        public static IAuthenticationInfo SetExpires( this IAuthenticationInfo @this, DateTime? expires ) => @this.SetExpires( expires, DateTime.UtcNow );

        /// <summary>
        /// Returns a new authentication information with <see cref="IAuthenticationInfo.CriticalExpires"/> sets
        /// to the new value (or this authentication info if it is the same).
        /// If the new <paramref name="criticalExpires"/> is greater than <see cref="IAuthenticationInfo.Expires"/>,
        /// the new Expires is automatically boosted to the new critical expires time. 
        /// </summary>
        /// <param name="this">This authentication info.</param>
        /// <param name="criticalExpires">The new CriticalExpires value.</param>
        /// <returns>The updated authentication info.</returns>
        public static IAuthenticationInfo SetCriticalExpires( this IAuthenticationInfo @this, DateTime? criticalExpires ) => @this.SetCriticalExpires( criticalExpires, DateTime.UtcNow );

        /// <summary>
        /// Removes impersonation if any (the <see cref="IAuthenticationInfo.ActualUser"/> 
        /// becomes the <see cref="IAuthenticationInfo.User"/>).
        /// </summary>
        /// <param name="this">This authentication info.</param>
        /// <returns>This or a new authentication info object.</returns>
        public static IAuthenticationInfo ClearImpersonation( this IAuthenticationInfo @this ) => @this.ClearImpersonation( DateTime.UtcNow );

    }
}
