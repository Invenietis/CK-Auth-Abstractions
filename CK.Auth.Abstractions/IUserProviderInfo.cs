using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.IO;

namespace CK.Auth
{
    /// <summary>
    /// Exposes provider <see cref="Name"/> and <see cref="LastUsed"/> by a <see cref="IUserInfo"/>.
    /// </summary>
    public interface IUserProviderInfo
    {
        /// <summary>
        /// Gets the provider name.
        /// This MUST never be null, empty or white spaces.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Gets the last time this provider has been used.
        /// This MUST always be in <see cref="DateTimeKind.Utc"/>.
        /// </summary>
        DateTime LastUsed { get; }
    }

}
