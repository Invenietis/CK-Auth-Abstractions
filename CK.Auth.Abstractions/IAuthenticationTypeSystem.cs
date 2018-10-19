using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System;
using System.IO;

namespace CK.Auth
{
    /// <summary>
    /// Type manager for <see cref="IAuthenticationInfo{TUserInfo}"/>.
    /// Defines "non instance" functionalities (that would have been non extensible static methods) like 
    /// builders and converters of the authentication info type.
    /// </summary>
    public interface IAuthenticationTypeSystem<TAuthInfo,TUserInfo> : StObjSupport.ISingletonAmbientService
        where TUserInfo : IUserInfo
        where TAuthInfo : IAuthenticationInfo<TUserInfo>
    {
        /// <summary>
        /// Gets the associated <see cref="IUserInfo"/> type manager.
        /// </summary>
        IUserInfoType<TUserInfo> UserInfoType { get; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="ToClaimsIdentity"/>
        /// and enforced by <see cref="FromClaimsIdentity"/>.
        /// Defaults to "CKA".
        /// <para>
        /// When exporting only the safe user claims (ignoring any potential impersonation), "-S" (for Simple) is
        /// appended (the default is then "CKA-S").
        /// </para>
        /// </summary>
        string ClaimAuthenticationType { get; }

        /// <summary>
        /// Gets the non authentication information: it has a <see cref="IAuthenticationInfo.Level"/> equals to
        /// <see cref="AuthLevel.None"/> and is semantically the same as a null reference (all authentication
        /// information with a None level are equivalent).
        /// Use <see cref="AuthenticationExtensions.IsNullOrNone(IAuthenticationInfo)">IsNullOrNone</see> to 
        /// easily test both cases.
        /// </summary>
        TAuthInfo None { get; }

        /// <summary>
        /// Creates a <see cref="TAuthInfo"/> from a ClaimsIdentity.
        /// Must return null if <paramref name="p"/> is null or if <see cref="ClaimsIdentity.AuthenticationType"/>
        /// is not the same as <see cref="IAuthenticationTypeSystem.ClaimAuthenticationType"/> or <see cref="IAuthenticationTypeSystem.ClaimAuthenticationTypeSimple"/>.
        /// </summary>
        /// <param name="p">The claims identity.</param>
        /// <returns>The extracted authentication info or null if <paramref name="p"/> is null.</returns>
        TAuthInfo FromClaimsIdentity( ClaimsIdentity p );

        /// <summary>
        /// Creates a <see cref="TAuthInfo"/> from a JObject.
        /// Must return null if <paramref name="o"/> is null.
        /// Must throw <see cref="InvalidDataException"/> if the o is not valid.
        /// </summary>
        /// <param name="o">The Json object.</param>
        /// <returns>The extracted authentication info or null if <paramref name="o"/> is null.</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the object is not in the expected format.
        /// </exception>
        TAuthInfo FromJObject( JObject o );

        /// <summary>
        /// Exports a <see cref="TAuthInfo"/> as a claims identity object.
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
        ClaimsIdentity ToClaimsIdentity( TAuthInfo info, bool userInfoOnly );

        /// <summary>
        /// Exports a <see cref="TAuthInfo"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null or none.
        /// (See <see cref="AuthenticationExtensions.IsNullOrNone(IAuthenticationInfo)">IsNullOrNone</see> extension method).
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        JObject ToJObject( TAuthInfo info );

        /// <summary>
        /// Writes the authentication information in binary format.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The authentication info to write. Can be null.</param>
        void Write( BinaryWriter w, TAuthInfo info );

        /// <summary>
        /// Reads a authentication information in binary format.
        /// Must throw <see cref="InvalidDataException"/> if the binary data is not valid.
        /// </summary>
        /// <param name="r">The binary reader (must not be null).</param>
        /// <returns>The authentication info. Can be null.</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the binary data can not be read.
        /// </exception>
        TAuthInfo Read( BinaryReader r );

    }
}
