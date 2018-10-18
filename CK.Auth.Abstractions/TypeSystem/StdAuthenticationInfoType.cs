using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System;
using System.IO;
using System.Threading;

namespace CK.Auth
{
    /// <summary>
    /// Defines "non instance" functionalities (that would have been non extensible static methods) like 
    /// builders and converters of the <see cref="IAuthenticationInfo"/> type.
    /// </summary>
    public class StdAuthenticationInfoType<T> : IAuthenticationInfoType where T : StdAuthenticationInfo
    {
        readonly IAuthenticationTypeSystem _typeSystem;
        readonly IUserInfoType _userType;
        readonly Lazy<T> _none;

        public StdAuthenticationInfoType( IAuthenticationTypeSystem typeSystem, IUserInfoType userType )
        {
            if( _userType == null ) throw new ArgumentNullException( nameof(userType) );
            _typeSystem = typeSystem;
            _userType = userType;
            _none = new Lazy<StdAuthenticationInfo>( () => CreateAuthenticationInfo( _userType.Anonymous, null ), LazyThreadSafetyMode.PublicationOnly );
        }

        /// <summary>
        /// Gets the non authentication information: it has a <see cref="IAuthenticationInfo.Level"/> equals to
        /// <see cref="AuthLevel.None"/> and is semantically the same as a null reference (all authentication
        /// information with a None level are equivalent).
        /// Use <see cref="AuthenticationExtensions.IsNullOrNone(IAuthenticationInfo)">IsNullOrNone</see> to 
        /// easily test both cases.
        /// </summary>
        IAuthenticationInfo None { get; }

        IAuthenticationInfo IAuthenticationInfoType.None => _none.Value;

        IAuthenticationInfo IAuthenticationInfoType.Create( IUserInfo user, DateTime? expires, DateTime? criticalExpires ) => CreateAuthenticationInfo( user, expires, criticalExpires );

        IAuthenticationInfo IAuthenticationInfoType.FromClaimsIdentity( ClaimsIdentity id )
        {
            if( id == null
                || (id.AuthenticationType != ClaimAuthenticationType && id.AuthenticationType != ClaimAuthenticationTypeSimple) )
            {
                return null;
            }
            IUserInfo actualUser = null;
            IUserInfo user = UserInfo.FromClaims( id.Claims );
            IEnumerable<Claim> actualActorClaims = id.Claims;
            if( id.Actor != null )
            {
                actualUser = UserInfo.FromClaims( id.Actor.Claims );
                actualActorClaims = id.Actor.Claims;
            }
            string exp = actualActorClaims.FirstOrDefault( c => c.Type == ExpirationKeyType )?.Value;
            var expires = exp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( exp ) ) : null;
            string criticalExp = actualActorClaims.FirstOrDefault( c => c.Type == CriticalExpirationKeyType )?.Value;
            var criticalExpires = criticalExp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( criticalExp ) ) : null;
            return AuthenticationInfoFromClaimsIdentity( actualUser, user, expires, criticalExpires, id, actualActorClaims );
        }

        IAuthenticationInfo IAuthenticationInfoType.FromJObject( JObject o ) => AuthenticationInfoFromJObject( o );

        ClaimsIdentity IAuthenticationInfoType.ToClaimsIdentity( IAuthenticationInfo info, bool userInfoOnly ) => AuthenticationInfoToClaimsIdentity( info, userInfoOnly );

        JObject IAuthenticationInfoType.ToJObject( IAuthenticationInfo info ) => AuthenticationInfoToJObject( info );

        void IAuthenticationInfoType.Write( BinaryWriter w, IAuthenticationInfo info )
        {
            if( w == null ) throw new ArgumentNullException( nameof( w ) );
            if( info.IsNullOrNone() ) w.Write( 0 );
            else
            {
                w.Write( 1 );
                int flag = 0;
                if( info.IsImpersonated ) flag |= 1;
                if( info.Expires.HasValue ) flag |= 2;
                if( info.CriticalExpires.HasValue ) flag |= 4;
                w.Write( (byte)flag );
                UserInfo.Write( w, info.UnsafeUser );
                if( info.IsImpersonated ) UserInfo.Write( w, info.UnsafeActualUser );
                if( info.Expires.HasValue ) w.Write( info.Expires.Value.ToBinary() );
                if( info.CriticalExpires.HasValue ) w.Write( info.CriticalExpires.Value.ToBinary() );
                WriteAuthenticationInfoRemainder( w, info );
            }
        }

        IAuthenticationInfo IAuthenticationInfoType.Read( BinaryReader r )
        {
            if( r == null ) throw new ArgumentNullException( nameof( r ) );
            try
            {
                int version = r.ReadInt32();
                if( version == 0 ) return null;
                int flags = r.ReadByte();
                IUserInfo user = UserInfo.Read( r );
                IUserInfo actualUser = null;
                DateTime? expires = null;
                DateTime? criticalExpires = null;
                if( (flags & 1) != 0 ) actualUser = UserInfo.Read( r );
                if( (flags & 2) != 0 ) expires = DateTime.FromBinary( r.ReadInt64() );
                if( (flags & 4) != 0 ) criticalExpires = DateTime.FromBinary( r.ReadInt64() );
                return ReadAuthenticationInfoRemainder( r, actualUser, user, expires, criticalExpires );
            }
            catch( Exception ex )
            {
                throw new InvalidDataException( "Invalid binary format.", ex );
            }
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.Create"/>.
        /// </summary>
        /// <param name="user">The unsafe user information. Can be null (the <see cref="IAuthenticationInfoType.None"/> must be returned).</param>
        /// <param name="expires">When null or already expired, Level is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Optional critical expiration.</param>
        /// <returns>The unsafe authentication information.</returns>
        protected virtual StdAuthenticationInfo CreateAuthenticationInfo( IUserInfo user, DateTime? expires, DateTime? criticalExpires = null )
        {
            return user == null ? _none.Value : new StdAuthenticationInfo( this, user, expires, criticalExpires );
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.ToJObject(IAuthenticationInfo)"/>.
        /// </summary>
        /// <param name="info">The authentication information.</param>
        /// <returns>Authentication information as a JObject.</returns>
        protected virtual JObject AuthenticationInfoToJObject( IAuthenticationInfo info )
        {
            if( info.IsNullOrNone() ) return null;
            var o = new JObject();
            o.Add( new JProperty( UserKeyType, UserInfoToJObject( info.UnsafeUser ) ) );
            if( info.IsImpersonated ) o.Add( new JProperty( ActualUserKeyType, UserInfoToJObject( info.UnsafeActualUser ) ) );
            if( info.Expires.HasValue ) o.Add( new JProperty( ExpirationKeyType, info.Expires ) );
            if( info.CriticalExpires.HasValue ) o.Add( new JProperty( CriticalExpirationKeyType, info.CriticalExpires ) );
            return o;
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.FromJObject(JObject)"/>.
        /// </summary>
        /// <param name="o">The JObject.</param>
        /// <returns>The authentication information.</returns>
        protected virtual IAuthenticationInfo AuthenticationInfoFromJObject( JObject o )
        {
            if( o == null ) return null;
            try
            {
                var user = UserInfoFromJObject( (JObject)o[UserKeyType] );
                var actualUser = UserInfoFromJObject( (JObject)o[ActualUserKeyType] );
                var expires = (DateTime?)o[ExpirationKeyType];
                var criticalExpires = (DateTime?)o[CriticalExpirationKeyType];
                return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires );
            }
            catch( Exception ex )
            {
                throw new InvalidDataException( o.ToString( Formatting.None ), ex );
            }
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>.
        /// It uses <see cref="ClaimAuthenticationType"/> as the <see cref="ClaimsIdentity.AuthenticationType"/>
        /// and the <see cref="ClaimsIdentity.Actor"/> for impersonation.
        /// </summary>
        /// <param name="info">The authentication information.</param>
        /// <param name="userInfoOnly">
        /// True to add (safe) user claims and ignore any impersonation.
        /// False to add unsafe user claims, a <see cref="AuthLevelKeyType"/> claim for the authentication level,
        /// the expirations if they exist and handle impersonation thanks to the <see cref="ClaimsIdentity.Actor"/>. 
        /// </param>
        /// <returns>Authentication information as a claim identity.</returns>
        protected virtual ClaimsIdentity AuthenticationInfoToClaimsIdentity( IAuthenticationInfo info, bool userInfoOnly )
        {
            if( info.IsNullOrNone() ) return null;
            ClaimsIdentity id = userInfoOnly
                                    ? new ClaimsIdentity( UserInfoToClaims( info.User ), ClaimAuthenticationTypeSimple, UserNameKeyType, null )
                                    : new ClaimsIdentity( UserInfoToClaims( info.UnsafeUser ), ClaimAuthenticationType, UserNameKeyType, null );
            ClaimsIdentity propertyBearer = id;
            if( !userInfoOnly )
            {
                if( info.IsImpersonated )
                {
                    id.Actor = propertyBearer = new ClaimsIdentity( UserInfoToClaims( info.UnsafeActualUser ), ClaimAuthenticationType, UserNameKeyType, null );
                }
                propertyBearer.AddClaim( new Claim( AuthLevelKeyType, info.Level.ToString() ) );
            }
            if( info.Expires.HasValue ) propertyBearer.AddClaim( new Claim( ExpirationKeyType, info.Expires.Value.ToUnixTimeSeconds().ToString() ) );
            if( info.CriticalExpires.HasValue ) propertyBearer.AddClaim( new Claim( CriticalExpirationKeyType, info.CriticalExpires.Value.ToUnixTimeSeconds().ToString() ) );
            return id;
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.FromClaimsIdentity(ClaimsIdentity)"/>.
        /// Note that <see cref="AuthLevelKeyType"/> claim is ignored: the final level depends
        /// on <see cref="ExpirationKeyType"/> and <see cref="CriticalExpirationKeyType"/>.
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
        protected virtual IAuthenticationInfo AuthenticationInfoFromClaimsIdentity(
            IUserInfo actualUser,
            IUserInfo user,
            DateTime? expires,
            DateTime? criticalExpires,
            ClaimsIdentity id,
            IEnumerable<Claim> actualActorClaims )
        {
            return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires );
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.Write(BinaryWriter, IAuthenticationInfo)"/>.
        /// Only extra properties to <see cref="IAuthenticationInfo"/> must be written.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The authentication info to write. Can be null.</param>
        protected virtual void WriteAuthenticationInfoRemainder( BinaryWriter w, IAuthenticationInfo info )
        {
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.Read(BinaryReader)"/>.
        /// Basic fields of <see cref="IAuthenticationInfo"/> are already read.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <param name="actualUser">Already read actual user.</param>
        /// <param name="user">Already read user.</param>
        /// <param name="expires">Already read expires.</param>
        /// <param name="criticalExpires">Already read critical expires.</param>
        /// <returns>The authentication info.</returns>
        private IAuthenticationInfo ReadAuthenticationInfoRemainder( BinaryReader r, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires )
        {
            return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires );
        }


    }
}
