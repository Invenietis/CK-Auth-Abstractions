using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace CK.Auth
{
    /// <summary>
    /// Unifies all types managers related to authentication.
    /// <see cref="StdAuthenticationTypeSystem"/> is an extensible of this type system.
    /// </summary>
    public interface IAuthenticationTypeSystem
    {
        /// <summary>
        /// Gets the <see cref="IUserInfoType"/> type manager.
        /// </summary>
        IUserInfoType UserInfo { get; }

        /// <summary>
        /// Gets the <see cref="IAuthenticationInfoType"/> type manager.
        /// </summary>
        IAuthenticationInfoType AuthenticationInfo { get; }

    }
}