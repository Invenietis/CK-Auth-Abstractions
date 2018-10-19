using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;

namespace CK.Auth
{
    /// <summary>
    /// Type handler for <see cref="IUserInfo"/>.
    /// Defines "non instance" functionalities (that would have been non extensible static methods) like 
    /// builders and converters of the <see cref="IUserInfo"/> type.
    /// </summary>
    public interface IUserInfoType<TUserInfo>
        where TUserInfo : IUserInfo
    {
        /// <summary>
        /// Gets the anonymous user info object.
        /// </summary>
        TUserInfo Anonymous { get; }

        /// <summary>
        /// Exports a <see cref="IUserInfo"/> to a list of claims.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The user info.</param>
        /// <returns>The claims or null if <paramref name="info"/> is null.</returns>
        List<Claim> ToClaims( TUserInfo info );

        /// <summary>
        /// Exports a <see cref="TUserInfo"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The user info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        JObject ToJObject( TUserInfo info );

        /// <summary>
        /// Creates a <see cref="TUserInfo"/> from a ClaimsIdentity.
        /// Must return null if <paramref name="id"/> is null.
        /// </summary>
        /// <param name="id">The claims.</param>
        /// <returns>The extracted user info or null if <paramref name="id"/> is null.</returns>
        TUserInfo FromClaims( IEnumerable<Claim> id );

        /// <summary>
        /// Creates a <see cref="TUserInfo"/> from a JObject.
        /// Must return null if <paramref name="o"/> is null.
        /// Must throw <see cref="InvalidDataException"/> if the o is not valid.
        /// </summary>
        /// <param name="o">The Json object.</param>
        /// <returns>The extracted user info or null if <paramref name="o"/> is null.</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the object is not in the expected format.
        /// </exception>
        TUserInfo FromJObject( JObject o );

        /// <summary>
        /// Writes the user information in binary format.
        /// </summary>
        /// <param name="w">The binary writer (must not be null).</param>
        /// <param name="info">The user info to write. Can be null.</param>
        void Write( BinaryWriter w, TUserInfo info );

        /// <summary>
        /// Reads a user information in binary format.
        /// Must throw <see cref="InvalidDataException"/> if the binary data is not valid.
        /// </summary>
        /// <param name="r">The binary reader (must not be null).</param>
        /// <returns>The user info. Can be null.</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the binary data can not be read.
        /// </exception>
        TUserInfo Read( BinaryReader r );
    }
}
