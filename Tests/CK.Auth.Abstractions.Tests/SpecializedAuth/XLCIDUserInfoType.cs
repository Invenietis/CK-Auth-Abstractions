using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Newtonsoft.Json.Linq;

namespace CK.Auth.Abstractions.Tests.SpecializedAuth
{
    public class XLCIDUserInfoType : StdUserInfoType<XLCIDUserInfo>
    {
        /// <summary>
        /// The name of the <see cref="XLCIDUserInfo.XLCID"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string XLCIDKeyType = "xlcid";

        protected override XLCIDUserInfo CreateAnonymous()
        {
            return new XLCIDUserInfo( 0, 0, null );
        }

        public override List<Claim> ToClaims( XLCIDUserInfo info )
        {
            if( info == null ) return null;
            var claims = base.ToClaims( info );
            claims.Add( new Claim( XLCIDKeyType, info.XLCID.ToString( CultureInfo.InvariantCulture ) ) );
            return claims;
        }

        protected override XLCIDUserInfo UserInfoFromClaims( int userId, string userName, IUserSchemeInfo[] schemes, IEnumerable<Claim> claims )
        {
            int xlcid = Int32.Parse( claims.First( c => c.Type == XLCIDKeyType ).Value, CultureInfo.InvariantCulture );
            return new XLCIDUserInfo( xlcid, userId, userName, schemes );
        }

        public override JObject ToJObject( XLCIDUserInfo info )
        {
            if( info == null ) return null;
            var o = base.ToJObject( info );
            o.Add( XLCIDKeyType, info.XLCID );
            return o;
        }

        protected override XLCIDUserInfo UserInfoFromJObject( int userId, string userName, StdUserSchemeInfo[] schemes, JObject o )
        {
            int xlcid = (int)o[XLCIDKeyType];
            return new XLCIDUserInfo( xlcid, userId, userName, schemes );
        }

        protected override void WriteUserInfoRemainder( BinaryWriter w, XLCIDUserInfo info )
        {
            w.Write( info.XLCID );
        }

        protected override XLCIDUserInfo ReadUserInfoRemainder( BinaryReader r, int userId, string userName, IUserSchemeInfo[] schemes )
        {
            int xlcid = r.ReadInt32();
            return new XLCIDUserInfo( xlcid, userId, userName, schemes );
        }

    }
}
