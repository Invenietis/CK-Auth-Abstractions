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
    public interface IAuthenticationInfoType<T> : IAuthenticationInfoType where T : IUserInfo
    {
        /// <summary>
        /// Creates a <see cref="IAuthenticationInfo{T}"/> from a ClaimsIdentity.
        /// Must return null if <paramref name="p"/> is null.
        /// </summary>
        /// <param name="p">The claims identity.</param>
        /// <returns>The extracted authentication info or null if <paramref name="p"/> is null.</returns>
        new IAuthenticationInfo<T> FromClaimsIdentity( ClaimsIdentity p );

        /// <summary>
        /// Creates a <see cref="IAuthenticationInfo{T}"/> from a JObject.
        /// Must return null if <paramref name="o"/> is null.
        /// </summary>
        /// <param name="o">The Json object.</param>
        /// <returns>The extracted authentication info or null if <paramref name="o"/> is null.</returns>
        new IAuthenticationInfo<T> FromJObject( JObject o );

        /// <summary>
        /// Exports a <see cref="IAuthenticationInfo{T}"/> as a claims identity object.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The claims or null if <paramref name="info"/> is null.</returns>
        ClaimsIdentity ToClaimsIdentity( IAuthenticationInfo<T> info );

        /// <summary>
        /// Exports a <see cref="IAuthenticationInfo{T}"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        JObject ToJObject( IAuthenticationInfo<T> info );

        /// <summary>
        /// Initializes a new <see cref="IAuthenticationInfo{T}"/> with <see cref="AuthLevel.Unsafe"/> level.
        /// </summary>
        /// <param name="user">The user (and actual user). Can be null.</param>
        IAuthenticationInfo<T> Create(T user);


        /// <summary>
        /// Writes the user information in binary format.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The user info to write. Can be null.</param>
        void Write(BinaryWriter w, IAuthenticationInfo<T> info);

        /// <summary>
        /// Reads a user information in binary format.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <returns>The user info. Can be null.</returns>
        new IAuthenticationInfo<T> Read(BinaryReader r);
    }
}