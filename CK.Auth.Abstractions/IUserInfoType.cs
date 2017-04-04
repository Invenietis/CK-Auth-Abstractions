using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

namespace CK.Auth
{
    /// <summary>
    /// Defines the core management functionalities of the <see cref="IUserInfo"/> type.
    /// </summary>
    public interface IUserInfoType
    {
        /// <summary>
        /// Gets the anonymous user info object.
        /// </summary>
        IUserInfo Anonymous { get; }

        /// <summary>
        /// Exports a <see cref="IUserInfo"/> to a ClaimsIdentity object.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The user info.</param>
        /// <returns>The claims or null if <paramref name="info"/> is null.</returns>
        ClaimsIdentity ToClaimsIdentity( IUserInfo info );

        /// <summary>
        /// Exports a <see cref="IUserInfo"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The user info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        JObject ToJObject( IUserInfo info );

        /// <summary>
        /// Creates a <see cref="IUserInfo"/> from a ClaimsIdentity.
        /// Must return null if <paramref name="id"/> is null.
        /// </summary>
        /// <param name="id">The claims identity.</param>
        /// <returns>The extracted authentication info or null if <paramref name="id"/> is null.</returns>
        IUserInfo FromClaimsIdentity( ClaimsIdentity id );

        /// <summary>
        /// Creates a <see cref="IUserInfo"/> from a JObject.
        /// Must return null if <paramref name="o"/> is null.
        /// </summary>
        /// <param name="o">The Json object.</param>
        /// <returns>The extracted user info or null if <paramref name="o"/> is null.</returns>
        IUserInfo FromJObject( JObject o );
    }
}