using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Claims;

namespace CK.Auth
{
    /// <summary>
    /// Standard implementation of <see cref="IAuthenticationTypeSystem"/>.
    /// This implementation is open to extension or can be reused (it also directly 
    /// implements <see cref="IAuthenticationInfoType"/> and <see cref="IUserInfoType"/>).
    /// </summary>
    public class StdAuthenticationTypeSystem : IAuthenticationTypeSystem, IAuthenticationInfoType, IUserInfoType
    {
        static readonly IUserInfo _anonymous = new StdUserInfo( 0, null, null );

        /// <summary>
        /// Gets the <see cref="IUserInfoType"/> type manager (actually, this object implements it).
        /// </summary>
        public IUserInfoType UserInfo => this;

        /// <summary>
        /// Gets the <see cref="IAuthenticationInfoType"/> type manager (actually, this object implements it).
        /// </summary>
        public IAuthenticationInfoType AuthenticationInfo => this;

        #region IUserInfo
        IUserInfo IUserInfoType.Anonymous => _anonymous;

        IUserInfo IUserInfoType.FromClaimsIdentity( ClaimsIdentity id ) => UserInfoFromClaimsIdentity( id );

        IUserInfo IUserInfoType.FromJObject( JObject o ) => UserInfoFromJObject( o );

        ClaimsIdentity IUserInfoType.ToClaimsIdentity( IUserInfo info ) => UserInfoToClaimsIdentity( info );

        JObject IUserInfoType.ToJObject( IUserInfo info ) => UserInfoToJObject( info );

        /// <summary>
        /// Implements <see cref="IUserInfoType.ToJObject(IUserInfo)"/>.
        /// </summary>
        /// <param name="info">The user information.</param>
        /// <returns>User information as a JObject.</returns>
        protected virtual JObject UserInfoToJObject( IUserInfo info )
        {
            if( info == null ) return null;
            return new JObject(
                    new JProperty( "actorId", info.ActorId ),
                    new JProperty( "displayName", info.DisplayName ),
                    new JProperty( "providers", new JArray( info.Providers.Select(
                           p => new JObject( new JProperty( "name", p.Name ), new JProperty( "lastUsed", p.LastUsed ) ) ) ) ) );
        }

        /// <summary>
        /// Implements <see cref="IUserInfoType.FromJObject(JObject)"/>.
        /// </summary>
        /// <param name="o">The JObject.</param>
        /// <returns>The user information.</returns>
        protected virtual IUserInfo UserInfoFromJObject( JObject o )
        {
            if( o == null ) return null;
            var actorId = (int)o["actorId"];
            if( actorId == 0 ) return _anonymous;
            var displayName = (string)o["displayName"];
            var providers = o["providers"].Select( p => new StdUserProviderInfo( (string)p["name"], (DateTime)p["lastUsed"] ) ).ToArray();
            return new StdUserInfo( actorId, displayName, providers );
        }

        /// <summary>
        /// Implements <see cref="IUserInfoType.ToClaimsIdentity(IUserInfo)"/>.
        /// Current implementation uses "CKA" as the <see cref="ClaimsIdentity.AuthenticationType"/>
        /// and adds a "sub" claim that contains the <see cref="UserInfoToJObject(IUserInfo)"/> json
        /// user information.
        /// </summary>
        /// <param name="info">The user information.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> object.</returns>
        protected virtual ClaimsIdentity UserInfoToClaimsIdentity( IUserInfo info )
        {
            if( info == null ) return null;
            var id = new ClaimsIdentity( "CKA" );
            string serialized = UserInfoToJObject( info ).ToString( Formatting.None );
            id.AddClaim( new Claim( "sub", serialized, null, null, null, id ) );
            return id;
        }

        /// <summary>
        /// Implements <see cref="IUserInfoType.FromClaimsIdentity(ClaimsIdentity)"/>.
        /// </summary>
        /// <param name="id">The ClaimsIdentity object.</param>
        /// <returns>Tue user information.</returns>
        protected virtual IUserInfo UserInfoFromClaimsIdentity( ClaimsIdentity id )
        {
            return id != null
                    ? UserInfoFromJObject( JObject.Parse( id.FindFirst( "sub" ).Value ) )
                    : null;
        }

        #endregion

        #region IAuthenticationInfo
        IAuthenticationInfo IAuthenticationInfoType.FromClaimsPrincipal( ClaimsPrincipal p ) => AuthenticationInfoFromClaimsPrincipal( p );

        IAuthenticationInfo IAuthenticationInfoType.FromJObject( JObject o ) => AuthenticationInfoFromJObject( o );

        ClaimsPrincipal IAuthenticationInfoType.ToClaimsPrincipal( IAuthenticationInfo info ) => AuthenticationInfoToClaimsPrincipal( info );

        JObject IAuthenticationInfoType.ToJObject( IAuthenticationInfo info ) => AuthenticationInfoToJObject( info );

        protected virtual JObject AuthenticationInfoToJObject( IAuthenticationInfo info )
        {
            if( info == null ) return null;
            var o = new JObject();
            o.Add( new JProperty( "user", UserInfoToJObject( info.UnsafeUser ) ) );
            if( info.IsImpersonated ) o.Add( new JProperty( "actualUser", UserInfoToJObject( info.UnsafeActualUser ) ) );
            if( info.Expires.HasValue ) o.Add( new JProperty( "expires", info.Expires ) );
            if( info.CriticalExpires.HasValue ) o.Add( new JProperty( "criticalExpires", info.CriticalExpires ) );
            return o;
        }

        protected virtual IAuthenticationInfo AuthenticationInfoFromJObject( JObject o )
        {
            if( o == null ) return null;
            var user = UserInfoFromJObject( (JObject)o["user"] );
            var actualUser = UserInfoFromJObject( (JObject)o["actualUser"] );
            var expires = (DateTime?)o["expires"];
            var criticalExpires = (DateTime?)o["criticalExpires"];
            return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires );
        }

        protected virtual ClaimsPrincipal AuthenticationInfoToClaimsPrincipal( IAuthenticationInfo info )
        {
            if( info == null ) return null;
            var p = new ClaimsPrincipal();
            ClaimsIdentity u;
            if( info.IsImpersonated )
            {
                var a = UserInfoToClaimsIdentity( info.UnsafeActualUser );
                u = UserInfoToClaimsIdentity( info.UnsafeUser );
                u.Actor = a;
                p.AddIdentity( u );
                p.AddIdentity( a );
            }
            else
            {
                u = UserInfoToClaimsIdentity( info.UnsafeUser );
                p.AddIdentity( u );
            }
            if( info.Expires.HasValue ) u.AddClaim( new Claim( "exp", info.Expires.Value.ToUnixTimeSeconds().ToString() ) );
            if( info.CriticalExpires.HasValue ) u.AddClaim( new Claim( "cexp", info.CriticalExpires.Value.ToUnixTimeSeconds().ToString() ) );
            return p;
        }

        protected virtual IAuthenticationInfo AuthenticationInfoFromClaimsPrincipal( ClaimsPrincipal p )
        {
            if( p == null ) return null;
            var u = p.Identities.First();
            var user = UserInfoFromClaimsIdentity( u );
            string exp = u.FindFirst( "exp" )?.Value;
            var expires = exp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( exp ) ) : null;
            string criticalExp = u.FindFirst( "cexp" )?.Value;
            var criticalExpires = criticalExp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( criticalExp ) ) : null;
            var actualUser = u.Actor != null ? UserInfoFromClaimsIdentity( u.Actor ) : null;
            return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires );
        }

        #endregion

    }
}
