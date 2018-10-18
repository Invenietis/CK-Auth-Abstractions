using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading;

namespace CK.Auth
{
    /// <summary>
    /// Standard implementation of <see cref="IAuthenticationTypeSystem"/>.
    /// This implementation is open to extension or can be reused (it also directly 
    /// implements <see cref="IAuthenticationInfoType"/>.
    /// </summary>
    public class StdAuthenticationTypeSystem : IAuthenticationTypeSystem, IAuthenticationInfoType
    {
        readonly StdUserInfoType _userType;
        Lazy<IAuthenticationInfo> _none;
        string _authenticationType = "CKA";
        static readonly IUserSchemeInfo[] _emptySchemes = new IUserSchemeInfo[0];

        /// <summary>
        /// Gets or sets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// Defaults to "CKA".
        /// </summary>
        public string ClaimAuthenticationType { get => _authenticationType; protected set => _authenticationType = value; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// when exporting only the saf user claims and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// Always equal to "<see cref="ClaimAuthenticationType"/>-S" (defaults to "CKA-S").
        /// </summary>
        public string ClaimAuthenticationTypeSimple => ClaimAuthenticationType + "-S";

        /// <summary>
        /// The name of the <see cref="IUserInfo.UserName"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string UserNameKeyType = "name";

        /// <summary>
        /// The name of the <see cref="IUserInfo.UserId"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string UserIdKeyType = "id";

        /// <summary>
        /// The name of the <see cref="IUserInfo.Schemes"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string SchemesKeyType = "schemes";

        /// <summary>
        /// The name of the <see cref="IAuthenticationInfo.Level"/> for the <see cref="Claim.Type"/>.
        /// </summary>
        public const string AuthLevelKeyType = "acr";

        /// <summary>
        /// The name of the <see cref="IAuthenticationInfo.Expires"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string ExpirationKeyType = "exp";

        /// <summary>
        /// The name of the <see cref="IAuthenticationInfo.CriticalExpires"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string CriticalExpirationKeyType = "cexp";

        /// <summary>
        /// The name of the <see cref="IAuthenticationInfo.UnsafeUser"/> for the JObject property name.
        /// </summary>
        public const string UserKeyType = "user";

        /// <summary>
        /// The name of the <see cref="IAuthenticationInfo.UnsafeActualUser"/> for the JObject property name.
        /// </summary>
        public const string ActualUserKeyType = "actualUser";

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationTypeSystem"/>.
        /// </summary>
        public StdAuthenticationTypeSystem()
        {
            _userType = new StdUserInfoType();
            _none = new Lazy<IAuthenticationInfo>( () => CreateAuthenticationInfo( _userType.Anonymous, null ), LazyThreadSafetyMode.PublicationOnly );
        }

        IUserInfoType IAuthenticationTypeSystem.UserInfo => _userType;

        /// <summary>
        /// Gets the <see cref="IUserInfoType"/> type manager.
        /// </summary>
        public StdUserInfoType UserInfo => _userType;

        /// <summary>
        /// Gets the <see cref="IAuthenticationInfoType"/> type manager (actually, this object implements it).
        /// </summary>
        public IAuthenticationInfoType AuthenticationInfo => this;

        #region IAuthenticationInfo

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
                ((IUserInfoType)UserInfo).Write( w, info.UnsafeUser );
                if( info.IsImpersonated ) ((IUserInfoType)UserInfo).Write( w, info.UnsafeActualUser );
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
                IUserInfo user = ((IUserInfoType)UserInfo).Read( r );
                IUserInfo actualUser = null;
                DateTime? expires = null;
                DateTime? criticalExpires = null;
                if( (flags & 1) != 0 ) actualUser = ((IUserInfoType)UserInfo).Read( r );
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
        protected virtual IAuthenticationInfo CreateAuthenticationInfo( IUserInfo user, DateTime? expires, DateTime? criticalExpires = null )
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
            o.Add( new JProperty( UserKeyType, UserInfo.ToJObject( info.UnsafeUser ) ) );
            if( info.IsImpersonated ) o.Add( new JProperty( ActualUserKeyType, UserInfo.ToJObject( info.UnsafeActualUser ) ) );
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
                var user = _userType.FromJObject( (JObject)o[UserKeyType] );
                var actualUser = _userType.FromJObject( (JObject)o[ActualUserKeyType] );
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
                                    ? new ClaimsIdentity( UserInfo.ToClaims( info.User ), ClaimAuthenticationTypeSimple, UserNameKeyType, null )
                                    : new ClaimsIdentity( UserInfo.ToClaims( info.UnsafeUser ), ClaimAuthenticationType, UserNameKeyType, null );
            ClaimsIdentity propertyBearer = id;
            if( !userInfoOnly )
            {
                if( info.IsImpersonated )
                {
                    id.Actor = propertyBearer = new ClaimsIdentity( UserInfo.ToClaims( info.UnsafeActualUser ), ClaimAuthenticationType, UserNameKeyType, null );
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

        #endregion

    }
}
