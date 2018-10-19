using System;
using System.Collections.Generic;
using System.Text;

namespace CK.Auth.Abstractions.Tests.SpecializedAuth
{
    public class XLCIDUserInfo : StdUserInfo
    {
        /// <summary>
        /// Initializes a new <see cref="XLCIDUserInfo"/>.
        /// </summary>
        /// <param name="xlcid">The XCLID identifier.</param>
        /// <param name="userId">The user identifier.</param>
        /// <param name="userName">The user name. Can be null or empty if and only if <paramref name="userId"/> is 0.</param>
        /// <param name="schemes">The schemes list.</param>
        public XLCIDUserInfo( int xlcid, int userId, string userName, IReadOnlyList<IUserSchemeInfo> schemes = null )
            : base( userId, userName, schemes )
        {
        }

        public int XLCID { get; }

        public XLCIDUserInfo SetXLCID( int xlcid )
        {
            return xlcid != XLCID
                    ? new XLCIDUserInfo( xlcid, UserId, UserName, Schemes )
                    : this;
        }

    }
}
