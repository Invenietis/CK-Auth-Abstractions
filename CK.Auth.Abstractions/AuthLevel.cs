using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CK.Auth
{
    /// <summary>
    /// Standard authentication levels.
    /// </summary>
    public enum AuthLevel
    {
        /// <summary>
        /// No authentication: this is the default value.
        /// The user is necessarily the anonymous.
        /// </summary>
        None = 0,
        /// <summary>
        /// The authentication information is not safe: it is issued from a 
        /// long lived cookie or other not very secure means.
        /// </summary>
        Unsafe = 1,
        /// <summary>
        /// Normal authentication level.
        /// </summary>
        Normal = 2,
        /// <summary>
        /// Critical level MUST be short term and rely on strong authentication 
        /// mechanisms (re-authentication, two-factor authentication, etc.).
        /// </summary>
        Critical = 3
    }
}
