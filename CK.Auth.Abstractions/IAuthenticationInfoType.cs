using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System;

namespace CK.Auth
{
    /// <summary>
    /// Defines the core management functionalities of the <see cref="IAuthenticationInfo"/> type.
    /// </summary>
    public interface IAuthenticationInfoType
    {
        /// <summary>
        /// Creates a <see cref="IAuthenticationInfo"/> from a ClaimsPrincipal.
        /// Must return null if <paramref name="p"/> is null.
        /// </summary>
        /// <param name="p">The claims principal.</param>
        /// <returns>The extracted authentication info or null if <paramref name="p"/> is null.</returns>
        IAuthenticationInfo FromClaimsPrincipal( ClaimsPrincipal p );

        /// <summary>
        /// Creates a <see cref="IAuthenticationInfo"/> from a JObject.
        /// Must return null if <paramref name="o"/> is null.
        /// </summary>
        /// <param name="o">The Json object.</param>
        /// <returns>The extracted authentication info or null if <paramref name="o"/> is null.</returns>
        IAuthenticationInfo FromJObject( JObject o );

        /// <summary>
        /// Exports a <see cref="IAuthenticationInfo"/> as a claims principal object.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The claims or null if <paramref name="info"/> is null.</returns>
        ClaimsPrincipal ToClaimsPrincipal( IAuthenticationInfo info );

        /// <summary>
        /// Exports a <see cref="IAuthenticationInfo"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        JObject ToJObject( IAuthenticationInfo info );
    }
}