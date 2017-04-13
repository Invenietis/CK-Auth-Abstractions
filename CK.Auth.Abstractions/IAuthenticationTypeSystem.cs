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
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// when exporting all the claims and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// Defaults to "CKA".
        /// </summary>
        string AuthenticationType { get; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// when exporting only the saf user claims and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// Always equal to "<see cref="AuthenticationType"/>-S" (defaults to "CKA-S").
        /// </summary>
        string AuthenticationTypeSimple { get; }

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