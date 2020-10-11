using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;
using System.Diagnostics.CodeAnalysis;

namespace CK.Auth
{
    /// <summary>
    /// Defines "non instance" functionalities (that would have been non extensible static methods) like 
    /// builders and converters of the <see cref="IUserInfo"/> type.
    /// </summary>
    public interface IUserInfoType
    {
        /// <summary>
        /// Gets the anonymous user info object.
        /// </summary>
        IUserInfo Anonymous { get; }

        /// <summary>
        /// Creates a new <see cref="IUserInfo"/>.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="userName">The user name. Can be null or empty if and only if <paramref name="userId"/> is 0.</param>
        /// <param name="schemes">The schemes list.</param>
        IUserInfo Create( int userId, string? userName, IReadOnlyList<IUserSchemeInfo>? schemes = null );

        /// <summary>
        /// Exports a <see cref="IUserInfo"/> to a list of claims.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The user info.</param>
        /// <returns>The claims or null if <paramref name="info"/> is null.</returns>
        [return: NotNullIfNotNull( "info" )]
        List<Claim>? ToClaims( IUserInfo? info );

        /// <summary>
        /// Exports a <see cref="IUserInfo"/> as a JObject.
        /// Must return null if <paramref name="info"/> is null.
        /// </summary>
        /// <param name="info">The user info.</param>
        /// <returns>The Json object or null if <paramref name="info"/> is null.</returns>
        [return: NotNullIfNotNull( "info" )]
        JObject? ToJObject( IUserInfo? info );

        /// <summary>
        /// Creates a <see cref="IUserInfo"/> from a ClaimsIdentity.
        /// Must return null if <paramref name="id"/> is null.
        /// </summary>
        /// <param name="id">The claims.</param>
        /// <returns>The extracted user info or null if <paramref name="id"/> is null.</returns>
        [return: NotNullIfNotNull( "id" )]
        IUserInfo? FromClaims( IEnumerable<Claim>? id );

        /// <summary>
        /// Creates a <see cref="IUserInfo"/> from a JObject.
        /// Must return null if <paramref name="o"/> is null.
        /// Must throw <see cref="InvalidDataException"/> if the o is not valid.
        /// </summary>
        /// <param name="o">The Json object.</param>
        /// <returns>The extracted user info or null if <paramref name="o"/> is null.</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the object is not in the expected format.
        /// </exception>
        [return: NotNullIfNotNull( "o" )]
        IUserInfo? FromJObject( JObject? o );

        /// <summary>
        /// Writes the user information in binary format.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The user info to write.</param>
        void Write( BinaryWriter w, IUserInfo? info );

        /// <summary>
        /// Reads a user information in binary format.
        /// Must throw <see cref="InvalidDataException"/> if the binary data is not valid.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <returns>The user info (or null since null is handled by <see cref="Write(BinaryWriter, IUserInfo?)"/>).</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the binary data can not be read.
        /// </exception>
        IUserInfo? Read( BinaryReader r );
    }
}
