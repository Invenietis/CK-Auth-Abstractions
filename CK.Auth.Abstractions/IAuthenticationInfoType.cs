using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System;
using System.IO;

namespace CK.Auth
{
    /// <summary>
    /// Defines "non instance" functionalities (that would have been non extensible static methods) like 
    /// builders and converters of the <see cref="IAuthenticationInfo"/> type.
    /// </summary>
    public interface IAuthenticationInfoType
    {
        /// <summary>
        /// Gets the non authentication information: it has a <see cref="IAuthenticationInfo.Level"/> equals to
        /// <see cref="AuthLevel.None"/> and is semantically the same as a null reference (all authentication
        /// information with a None level are equivalent).
        /// Use <see cref="AuthenticationExtensions.IsNullOrNone(IAuthenticationInfo)">IsNullOrNone</see> to 
        /// easily test both cases.
        /// </summary>
        IAuthenticationInfo None { get; }

        /// <summary>
        /// Creates a new <see cref="IAuthenticationInfo"/>.
        /// </summary>
        /// <param name="user">The user (and actual user). Can be null.</param>
        /// <param name="expires">When null or already expired, Level is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Optional critical expiration.</param>
        IAuthenticationInfo Create(IUserInfo user, DateTime? expires = null, DateTime? criticalExpires = null);

        /// <summary>
        /// Creates a <see cref="IAuthenticationInfo"/> from a ClaimsIdentity.
        /// Must return null if <paramref name="p"/> is null or if <see cref="ClaimsIdentity.AuthenticationType"/>
        /// is not the same as <see cref="IAuthenticationTypeSystem.ClaimAuthenticationType"/> or <see cref="IAuthenticationTypeSystem.ClaimAuthenticationTypeSimple"/>.
        /// </summary>
        /// <param name="p">The claims identity.</param>
        /// <returns>The extracted authentication info or null if <paramref name="p"/> is null.</returns>
        IAuthenticationInfo FromClaimsIdentity( ClaimsIdentity p );

        /// <summary>
        /// Creates a <see cref="IAuthenticationInfo"/> from a JObject.
        /// Must return null if <paramref name="o"/> is null.
        /// </summary>
        /// <param name="o">The Json object.</param>
        /// <returns>The extracted authentication info or null if <paramref name="o"/> is null.</returns>
        IAuthenticationInfo FromJObject( JObject o );

        /// <summary>
        /// Exports a <see cref="IAuthenticationInfo"/> as a claims identity object.
        /// Must return null if <paramref name="info"/> is null or none.
        /// (See <see cref="AuthenticationExtensions.IsNullOrNone(IAuthenticationInfo)">IsNullOrNone</see> extension method).
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <param name="userInfoOnly">
        /// True to add (safe) user claims and ignore any impersonation.
        /// False to add unsafe user claims, a claim for the authentication level,
        /// the expirations if they exist and handle impersonation thanks to the <see cref="ClaimsIdentity.Actor"/>. 
        /// </param>
        /// <returns>The claims or null if <paramref name="info"/> is null.</returns>
        ClaimsIdentity ToClaimsIdentity( IAuthenticationInfo info, bool userInfoOnly);

        /// <summary>
        /// Exports a <see cref="IAuthenticationInfo"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null or none.
        /// (See <see cref="AuthenticationExtensions.IsNullOrNone(IAuthenticationInfo)">IsNullOrNone</see> extension method).
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        JObject ToJObject( IAuthenticationInfo info );

        /// <summary>
        /// Writes the authentication information in binary format.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The authentication info to write. Can be null.</param>
        void Write(BinaryWriter w, IAuthenticationInfo info);

        /// <summary>
        /// Reads a authentication information in binary format.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <returns>The authentication info. Can be null.</returns>
        IAuthenticationInfo Read(BinaryReader r);


    }
}