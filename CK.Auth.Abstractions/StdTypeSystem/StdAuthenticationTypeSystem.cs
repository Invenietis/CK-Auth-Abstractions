using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System;
using System.IO;
using System.Threading;
using System.Linq;
using Newtonsoft.Json;

namespace CK.Auth
{
    /// <summary>
    /// Implementation of <see cref="IAuthenticationTypeSystem"/> that handles <see cref="StdAuthenticationInfo"/>
    /// and <see cref="StdUserInfo"/>.
    /// </summary>
    public class StdAuthenticationTypeSystem : StdAuthenticationTypeSystem<StdAuthenticationInfo,StdUserInfo>
    {
        public StdAuthenticationTypeSystem( StdUserInfoType userInfoType )
            : base( userInfoType )
        {
        }

        /// <summary>
        /// Gets the associated user info type.
        /// </summary>
        public new StdUserInfoType UserInfoType => (StdUserInfoType)base.UserInfoType;

        protected override StdAuthenticationInfo AuthenticationInfoFromClaimsIdentity( StdUserInfo actualUser, StdUserInfo user, DateTime? expires, DateTime? criticalExpires, ClaimsIdentity id, IEnumerable<Claim> actualActorClaims )
        {
            return new StdAuthenticationInfo( UserInfoType, actualUser, user, expires, criticalExpires );
        }

        protected override StdAuthenticationInfo AuthenticationInfoFromJObject( StdUserInfo actualUser, StdUserInfo user, DateTime? expires, DateTime? criticalExpires, JObject o )
        {
            return new StdAuthenticationInfo( UserInfoType, actualUser, user, expires, criticalExpires );
        }

        protected override StdAuthenticationInfo CreateNone()
        {
            return new StdAuthenticationInfo( UserInfoType, null );
        }

        protected override StdAuthenticationInfo ReadAuthenticationInfoRemainder( BinaryReader r, StdUserInfo actualUser, StdUserInfo user, DateTime? expires, DateTime? criticalExpires )
        {
            return new StdAuthenticationInfo( UserInfoType, actualUser, user, expires, criticalExpires );
        }

        protected override void WriteAuthenticationInfoRemainder( BinaryWriter w, StdAuthenticationInfo info )
        {
        }
    }
}
