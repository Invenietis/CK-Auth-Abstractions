using CK.Core;
using System.Security.Claims;

namespace CK.Auth
{
    /// <summary>
    /// Unifies all types managers related to authentication.
    /// <see cref="StdAuthenticationTypeSystem"/> is an extensible implementation of this type system.
    /// </summary>
    public interface IAuthenticationTypeSystem : IAmbientServiceDefaultProvider<IAuthenticationInfo>
    {
        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// when exporting all the claims and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// The <see cref="ClaimAuthenticationTypeSimple"/> is derived from this value.
        /// Defaults to "CKA".
        /// </summary>
        string ClaimAuthenticationType { get; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// when exporting only the safe user claims and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// Always equal to "<see cref="ClaimAuthenticationType"/>-S" (defaults to "CKA-S").
        /// </summary>
        string ClaimAuthenticationTypeSimple { get; }

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
