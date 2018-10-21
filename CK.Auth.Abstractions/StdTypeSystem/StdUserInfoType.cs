using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace CK.Auth
{
    /// <summary>
    /// Implementation of <see cref="StdUserInfoType{TUserInfo}"/> that handles <see cref="StdUserInfo"/>.
    /// </summary>
    public sealed class StdUserInfoType : StdUserInfoType<StdUserInfo>
    {
        /// <summary>
        /// Creates a new <see cref="StdUserInfo"/>.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="userName">The user name. Can be null or empty if and only if <paramref name="userId"/> is 0.</param>
        /// <param name="schemes">The schemes list.</param>
        public StdUserInfo Create( int userId, string userName, IReadOnlyList<IUserSchemeInfo> schemes = null )
        {
            return new StdUserInfo( userId, userName, schemes );
        }

        /// <summary>
        /// Creates the anonymous <see cref="StdUserInfo"/>.
        /// </summary>
        /// <returns></returns>
        protected override StdUserInfo CreateAnonymous() => new StdUserInfo( 0, null, null );

        /// <summary>
        /// Simply returns a new <see cref="StdUserInfo"/>.
        /// </summary>
        /// <param name="userId">The value read from <see cref="UserIdKeyType"/> claim.</param>
        /// <param name="userName">The value read from <see cref="UserNameKeyType"/> claim.</param>
        /// <param name="schemes">The Array read from <see cref="SchemesKeyType"/> claim.</param>
        /// <param name="claims">All the Claims (including the 3 already extracted ones).</param>
        /// <returns>The user information.</returns>
        protected override StdUserInfo UserInfoFromClaims( int userId, string userName, IUserSchemeInfo[] schemes, IEnumerable<Claim> claims )
        {
            return new StdUserInfo( userId, userName, schemes );
        }

        /// <summary>
        /// Simply returns a new <see cref="StdUserInfo"/>.
        /// </summary>
        /// <param name="userId">The already read user identifier.</param>
        /// <param name="userName">The already read userName.</param>
        /// <param name="schemes">The already read schemes array.</param>
        /// <param name="o">The JObject that may be used to extract any extra field.</param>
        /// <returns>The user information.</returns>
        protected override StdUserInfo UserInfoFromJObject( int userId, string userName, StdUserSchemeInfo[] schemes, JObject o )
        {
            return new StdUserInfo( userId, userName, schemes );
        }

        /// <summary>
        /// Simply returns a new <see cref="StdUserInfo"/>.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <param name="userId">Already read user identifier.</param>
        /// <param name="userName">Already read user name.</param>
        /// <param name="schemes">Already read providers.</param>
        /// <returns>The user info.</returns>
        protected override StdUserInfo ReadUserInfoRemainder( BinaryReader r, int userId, string userName, IUserSchemeInfo[] schemes )
        {
            return new StdUserInfo( userId, userName, schemes );
        }

        /// <summary>
        /// Does nothing since <see cref="StdUserInfo"/> has no extra data by definition.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The user information.</param>
        protected override void WriteUserInfoRemainder( BinaryWriter w, StdUserInfo info )
        {
        }
    }
}
