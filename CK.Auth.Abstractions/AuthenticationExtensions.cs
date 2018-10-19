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
        public static bool IsNullOrNone<TUserInfo>( this IAuthenticationInfo<TUserInfo> @this )
            where TUserInfo : IUserInfo
            => @this == null || @this.Level == AuthLevel.None;

    }
}
