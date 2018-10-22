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
    /// Intermediate class that enables to avoid the duplicated <typeparamref name="TAuthInfo"/>
    /// required by the actual <see cref="StdAuthenticationTypeSystem{TAuthInfo, TUserInfo, TAuthInfo}"/>.
    /// </summary>
    /// <typeparam name="TAuthInfo">Type of the authentication info.</typeparam>
    /// <typeparam name="TUserInfo">Type of the user info.</typeparam>
    public abstract class StdAuthenticationTypeSystem<TAuthInfo, TUserInfo> : StdAuthenticationTypeSystemBase<TAuthInfo, TUserInfo, TAuthInfo>
        where TAuthInfo : StdAuthenticationInfo<TUserInfo, TAuthInfo>
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
