using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.IO;

namespace CK.Auth;

/// <summary>
/// Captures authentication scheme use.
/// </summary>
public sealed class UserSchemeInfo
{
    /// <summary>
    /// Initializes a new <see cref="UserSchemeInfo"/>.
    /// </summary>
    /// <param name="name">Scheme name must not be null, empty or white spaces.</param>
    /// <param name="lastUsed">Last used must be a <see cref="DateTimeKind.Utc"/> or <see cref="DateTimeKind.Unspecified"/> date.</param>
    public UserSchemeInfo( string name, DateTime lastUsed )
    {
        if( string.IsNullOrWhiteSpace( name ) ) throw new ArgumentException();
        if( lastUsed.Kind == DateTimeKind.Local ) throw new ArgumentException( "Kind must be Utc or Unspecified, not Local." );
        Name = name;
        LastUsed = lastUsed.Kind == DateTimeKind.Unspecified
                        ? DateTime.SpecifyKind( lastUsed, DateTimeKind.Utc )
                        : lastUsed;
    }

    /// <summary>
    /// See <see cref="UserSchemeInfo.Name"/>.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// See <see cref="UserSchemeInfo.LastUsed"/>.
    /// </summary>
    public DateTime LastUsed { get; }

}
