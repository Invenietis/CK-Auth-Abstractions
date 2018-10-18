using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Text;
using Newtonsoft.Json.Linq;

namespace CK.Auth.Abstractions.Tests.SpecializedAuth
{
    public class TenantAuthenticationTypeSystem : StdAuthenticationTypeSystem, IAuthenticationInfoType<TenantAuthenticationInfo>
    {
        TenantAuthenticationInfo IAuthenticationInfoType<TenantAuthenticationInfo>.None => AuthenticationInfo.None;

        public new IAuthenticationInfoType<TenantAuthenticationInfo> AuthenticationInfo => this;

        protected override IAuthenticationInfo CreateAuthenticationInfo( IUserInfo user, DateTime? expires, DateTime? criticalExpires = null )
        {
            return user == null ? _none.Value : new StdAuthenticationInfo( this, user, expires, criticalExpires );
        }
    }
}
