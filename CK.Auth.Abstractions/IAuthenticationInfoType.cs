using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System;
using System.IO;

namespace CK.Auth
{
    /// <summary>
    /// Defines the core management functionalities of the <see cref="IAuthenticationInfo"/> type.
    /// </summary>
    public interface IAuthenticationInfoType
    {
        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="ToClaimsIdentity(IAuthenticationInfo)"/>
        /// and enforced by <see cref="FromClaimsIdentity(ClaimsIdentity)"/>.
        /// Defaults to "CKA".
        /// </summary>
        string AuthenticationType { get; }

        /// <summary>
        /// Creates a <see cref="IAuthenticationInfo"/> from a ClaimsIdentity.
        /// Must return null if <paramref name="p"/> is null or if <see cref="ClaimsIdentity.AuthenticationType"/>
        /// is not the same as <see cref="AuthenticationType"/>.
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
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The claims or null if <paramref name="info"/> is null.</returns>
        ClaimsIdentity ToClaimsIdentity( IAuthenticationInfo info );

        /// <summary>
        /// Exports a <see cref="IAuthenticationInfo"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        JObject ToJObject( IAuthenticationInfo info );

        /// <summary>
        /// Initializes a new <see cref="IAuthenticationInfo"/>.
        /// </summary>
        /// <param name="user">The user (and actual user). Can be null.</param>
        /// <param name="expires">When null or already expired, Level is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Optional critical expiration.</param>
        IAuthenticationInfo Create(IUserInfo user, DateTime? expires, DateTime? criticalExpires = null);

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