using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace CK.Auth
{
    /// <summary>
    /// Implementation of <see cref="IUserInfoType"/> that handles <see cref="StdUserInfo"/>.
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

        protected override StdUserInfo CreateAnonymous() => new StdUserInfo( 0, null, null );

        protected override StdUserInfo UserInfoFromClaims( int userId, string userName, IUserSchemeInfo[] schemes, IEnumerable<Claim> claims )
        {
            return new StdUserInfo( userId, userName, schemes );
        }

        protected override StdUserInfo UserInfoFromJObject( int userId, string userName, StdUserSchemeInfo[] schemes, JObject o )
        {
            return new StdUserInfo( userId, userName, schemes );
        }

        protected override StdUserInfo ReadUserInfoRemainder( BinaryReader r, int userId, string userName, IUserSchemeInfo[] schemes )
        {
            return new StdUserInfo( userId, userName, schemes );
        }

        protected override void WriteUserInfoRemainder( BinaryWriter w, StdUserInfo info )
        {
        }
    }
}
