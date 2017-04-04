using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.Auth
{
    /// <summary>
    /// Small helpers to help handle <see cref="UnixEpoch"/> date conversions.
    /// </summary>
    public static class AuthenticationExtensions
    {
        /// <summary>
        /// Handles expiration checks by returning an updated information whenever <see cref="Expires"/>
        /// or <see cref="CriticalExpires"/> are greater than <see cref="DateTime.UtcNow"/>.
        /// </summary>
        /// <returns>This or an updated authentication information.</returns>
        public static IAuthenticationInfo CheckExpiration(this IAuthenticationInfo @this) => @this.CheckExpiration(DateTime.UtcNow);

    }
}
