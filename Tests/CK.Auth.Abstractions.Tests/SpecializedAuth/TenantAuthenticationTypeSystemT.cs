using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Claims;
using System.Text;
using Newtonsoft.Json.Linq;

namespace CK.Auth.Abstractions.Tests.SpecializedAuth
{
    public class TenantAuthenticationTypeSystem<TUserInfo> : StdAuthenticationTypeSystem<TenantAuthenticationInfo<TUserInfo>, TUserInfo>
        where TUserInfo : StdUserInfo
    {
        public const string TenantIdKeyType = "tenant";

        public TenantAuthenticationTypeSystem( StdUserInfoType<TUserInfo> userInfoType )
            : base( userInfoType )
        {
        }

        /// <summary>
        /// Helper to create a new <see cref="TenantAuthenticationInfo"/>.
        /// This is specific to this class, this method can not appear on any interface unless
        /// a (quite useless) ITenantAuthenticationInfo&lt;TUserInfo&gt; interface is defined.
        /// </summary>
        /// <returns>The new authentication info.</returns>
        public TenantAuthenticationInfo<TUserInfo> Create( int tenantId, TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires )
        {
            return new TenantAuthenticationInfo<TUserInfo>( UserInfoType, tenantId, actualUser, user, expires, criticalExpires, DateTime.UtcNow );
        }

        /// <summary>
        /// Creates the "None" authentication info.
        /// Note that a null authentication info is semantically equivalent to this None.
        /// </summary>
        /// <returns></returns>
        protected override TenantAuthenticationInfo<TUserInfo> CreateNone()
        {
            return new TenantAuthenticationInfo<TUserInfo>( UserInfoType, 0, null, null );
        }

        /// <summary>
        /// Must return null when <paramref name="info"/> is null or none
        /// (see <see cref="AuthenticationExtensions.IsNullOrNone{TUserInfo}(IAuthenticationInfo{TUserInfo})">IsNullOrNone()</see>
        /// extension method).
        /// Adds the <see cref="TenantIdKeyType"/> as a claim otherwise.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The claim identity.</returns>
        public override ClaimsIdentity ToClaimsIdentity( TenantAuthenticationInfo<TUserInfo> info, bool userInfoOnly )
        {
            if( info.IsNullOrNone() ) return null;
            var id = base.ToClaimsIdentity( info, userInfoOnly );
            id.AddClaim( new Claim( TenantIdKeyType, info.TenantId.ToString( CultureInfo.InvariantCulture ) ) );
            return id;
        }

        /// <summary>
        /// Implements ultimate step of <see cref="FromClaimsIdentity(ClaimsIdentity)"/>.
        /// This simply reads the <see cref="TenantIdKeyType"/> claim.
        /// </summary>
        /// <param name="actualUser">The actual user (from <see cref="ClaimsIdentity.Actor"/>).</param>
        /// <param name="user">The user information.</param>
        /// <param name="expires">The expiration.</param>
        /// <param name="criticalExpires">The critical expiration.</param>
        /// <param name="id">
        /// The claims identity (its AuthenticationType is either <see cref="ClaimAuthenticationType"/>
        /// or <see cref="ClaimAuthenticationTypeSimple"/>).
        /// </param>
        /// <param name="actualActorClaims">
        /// The <see cref="ClaimsIdentity.Actor"/> claims when impersonation is active,
        /// otherwise it is the <paramref name="id"/>'s Claims.
        /// </param>
        /// <returns>The authentication information.</returns>
        protected override TenantAuthenticationInfo<TUserInfo> AuthenticationInfoFromClaimsIdentity( TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires, ClaimsIdentity id, IEnumerable<Claim> actualActorClaims )
        {
            int tenantId = Int32.Parse( id.FindFirst( TenantIdKeyType ).Value, CultureInfo.InvariantCulture );
            return new TenantAuthenticationInfo<TUserInfo>( UserInfoType, tenantId, actualUser, user, expires, criticalExpires, DateTime.UtcNow );
        }

        /// <summary>
        /// Must return null when <paramref name="info"/> is null or none
        /// (see <see cref="AuthenticationExtensions.IsNullOrNone{TUserInfo}(IAuthenticationInfo{TUserInfo})">IsNullOrNone()</see>
        /// extension method).
        /// Adds the <see cref="TenantIdKeyType"/> in the JObject otherwise.
        /// </summary>
        /// <param name="info">The authentication info.</param>
        /// <returns>The JSON representation.</returns>
        public override JObject ToJObject( TenantAuthenticationInfo<TUserInfo> info )
        {
            if( info.IsNullOrNone() ) return null;
            var o = base.ToJObject( info );
            o.Add( TenantIdKeyType, info.TenantId );
            return o;
        }

        /// <summary>
        /// Reads the <see cref="TenantIdKeyType"/> property and returns a new <see cref="TenantAuthenticationInfo"/>.
        /// </summary>
        /// <param name="actualUser">The already read actual user.</param>
        /// <param name="user">The already read user.</param>
        /// <param name="expires">The already read expiration.</param>
        /// <param name="criticalExpires">The already read critical expiration.</param>
        /// <param name="o">The JSON object.</param>
        /// <returns>A new authentication info object.</returns>
        protected override TenantAuthenticationInfo<TUserInfo> AuthenticationInfoFromJObject( TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires, JObject o )
        {
            int tenantId = (int)o[TenantIdKeyType];
            return new TenantAuthenticationInfo<TUserInfo>( UserInfoType, tenantId, actualUser, user, expires, criticalExpires, DateTime.UtcNow );
        }

        /// <summary>
        /// Writes the <see cref="TenantAuthenticationInfo.TenantId"/>.
        /// </summary>
        /// <param name="w">The writer to use.</param>
        /// <param name="info">The authentication info to write.</param>
        protected override void WriteAuthenticationInfoRemainder( BinaryWriter w, TenantAuthenticationInfo<TUserInfo> info )
        {
            w.Write( info.TenantId );
        }

        /// <summary>
        /// Reads the <see cref="TenantAuthenticationInfo.TenantId"/> and returns a new <see cref="TenantAuthenticationInfo"/>. 
        /// </summary>
        /// <param name="r">The reader to use.</param>
        /// <param name="actualUser">The already read actual user.</param>
        /// <param name="user">The already read user.</param>
        /// <param name="expires">The already read expiration.</param>
        /// <param name="criticalExpires">The already read critical expiration.</param>
        /// <returns>A new authentication info object.</returns>
        protected override TenantAuthenticationInfo<TUserInfo> ReadAuthenticationInfoRemainder( BinaryReader r, TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires )
        {
            int tenantId = r.ReadInt32();
            return new TenantAuthenticationInfo<TUserInfo>( UserInfoType, tenantId, actualUser, user, expires, criticalExpires, DateTime.UtcNow );
        }

    }
}
