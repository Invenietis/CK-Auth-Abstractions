using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.IO;

namespace CK.Auth;

/// <summary>
/// Exposes scheme <see cref="Name"/> and <see cref="LastUsed"/> by a <see cref="IUserInfo"/>.
/// </summary>
public interface IUserSchemeInfo
{
    /// <summary>
    /// Gets the scheme name.
    /// This MUST never be null, empty or white spaces.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Gets the last time this scheme has been used.
    /// This MUST always be in <see cref="DateTimeKind.Utc"/>.
    /// </summary>
    DateTime LastUsed { get; }
}
