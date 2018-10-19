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
    public abstract class StdAuthenticationTypeSystem<TUserInfo> : StdAuthenticationTypeSystem<StdAuthenticationInfo<TUserInfo>, TUserInfo>
        where TUserInfo : StdUserInfo
    {

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationTypeSystem{TAuthInfo, TUserInfo}"/> that uses
        /// the given <see cref="IUserInfo"/> type handler instance. 
        /// </summary>
        /// <param name="userInfoType">User info type handler.</param>
        public StdAuthenticationTypeSystem( StdUserInfoType<TUserInfo> userInfoType )
            : base( userInfoType )
        {
        }

    }

}
