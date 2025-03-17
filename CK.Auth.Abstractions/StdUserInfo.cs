using System;
using System.Collections.Generic;

namespace CK.Auth;

/// <summary>
/// Standard immutable implementation of <see cref="IUserInfo"/>.
/// </summary>
public class StdUserInfo : IUserInfo
{
    static readonly UserSchemeInfo[] _emptySchemes = new UserSchemeInfo[0];

    /// <summary>
    /// Initializes a new <see cref="StdUserInfo"/>.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="userName">The user name. Can be null or empty if and only if <paramref name="userId"/> is 0.</param>
    /// <param name="schemes">The schemes list.</param>
    public StdUserInfo( int userId, string? userName, IReadOnlyList<UserSchemeInfo>? schemes = null )
    {
        UserId = userId;
        UserName = userName ?? string.Empty;
        if( (UserName.Length == 0) != (userId == 0) ) throw new ArgumentException( $"UserName ('{userName}') is empty == {userId} is 0." );
        Schemes = schemes ?? _emptySchemes;
    }

    /// <summary>
    /// See <see cref="IUserInfo.UserId"/>.
    /// </summary>
    public int UserId { get; }

    /// <summary>
    /// See <see cref="IUserInfo.UserName"/>.
    /// </summary>
    public string UserName { get; }

    /// <summary>
    /// See <see cref="IUserInfo.Schemes"/>.
    /// </summary>
    public IReadOnlyList<UserSchemeInfo> Schemes { get; }

}
