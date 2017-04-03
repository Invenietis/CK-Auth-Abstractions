using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CK.Auth
{
    /// <summary>
    /// Small helpers to help handle <see cref="UnixEpoch"/> date conversions.
    /// </summary>
    public static class DateTimeExtensions
    {
        /// <summary>
        /// The UTC Unix epoch (1970-1-1T00:00:00Z).
        /// </summary>
        public static readonly DateTime UnixEpoch = new DateTime( 1970, 1, 1, 0, 0, 0, DateTimeKind.Utc );

        /// <summary>
        /// Converts this <see cref="DateTime"/> to milliseconds based on <see cref="UnixEpoch"/>.
        /// </summary>
        /// <param name="this">This DateTime.</param>
        /// <returns>Number of milliseconds since <see cref="UnixEpoch"/>.</returns>
        public static long ToUnixTimeMilliseconds( this DateTime @this )
        {
            return (long)(@this - UnixEpoch).TotalMilliseconds;
        }

        /// <summary>
        /// Converts this <see cref="DateTime"/> to seconds based on <see cref="UnixEpoch"/>.
        /// </summary>
        /// <param name="this">This DateTime.</param>
        /// <returns>Number of seconds since <see cref="UnixEpoch"/>.</returns>
        public static long ToUnixTimeSeconds( this DateTime @this )
        {
            return (long)(@this - UnixEpoch).TotalSeconds;
        }

    }
}
