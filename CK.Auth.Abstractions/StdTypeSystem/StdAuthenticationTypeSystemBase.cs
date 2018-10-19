using System.Security.Claims;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System;
using System.IO;
using System.Threading;
using System.Linq;
using Newtonsoft.Json;

namespace CK.Auth
{
    /// <summary>
    /// Standard type handler implementation for <see cref="StdAuthenticationInfo"/> and <see cref="StdUserInfo"/>.
    /// Defines "non instance" functionalities (that would have been non extensible static methods) like 
    /// builders and converters of the <see cref="IAuthenticationInfo"/> type.
    /// </summary>
    public abstract class StdAuthenticationTypeSystemBase<TAuthInfo,TUserInfo,TFinalAuthInfo> : IAuthenticationTypeSystem<TFinalAuthInfo, TUserInfo>
    where TAuthInfo : StdAuthenticationInfo<TUserInfo, TAuthInfo>
    where TFinalAuthInfo : TAuthInfo
    where TUserInfo : StdUserInfo
    {
        string _authenticationType = "CKA";

        /// <summary>
        /// Gets or sets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationTypeSystem.ToClaimsIdentity"/>
        /// and enforced by <see cref="IAuthenticationTypeSystem.FromClaimsIdentity"/>.
        /// Defaults to "CKA".
        /// </summary>
        public string ClaimAuthenticationType { get => _authenticationType; protected set => _authenticationType = value; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationTypeSystem.ToClaimsIdentity"/>
        /// when exporting only the safe user claims and enforced by <see cref="IAuthenticationTypeSystem.FromClaimsIdentity"/>.
        /// Always equal to "<see cref="ClaimAuthenticationType"/>-S" (defaults to "CKA-S").
        /// </summary>
        public string ClaimAuthenticationTypeSimple => ClaimAuthenticationType + "-S";

        /// <summary>
        /// The name of the <see cref="IAuthenticationInfo.User"/> or <see cref="IAuthenticationInfo.UnsafeUser"/>
        /// for the <see cref="Claim.Type"/> and JObject property name.
        /// </summary>
        public const string UserNameKeyType = "name";

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

        readonly StdUserInfoType<TUserInfo> _userType;
        readonly Lazy<TFinalAuthInfo> _none;

         protected StdAuthenticationTypeSystemBase( StdUserInfoType<TUserInfo> userInfoType )
        {
            if( userInfoType == null ) throw new ArgumentNullException( nameof(userInfoType) );
            _userType = userInfoType;
            _none = new Lazy<TFinalAuthInfo>( () => CreateNone(), LazyThreadSafetyMode.PublicationOnly );
        }

        IUserInfoType<TUserInfo> IAuthenticationTypeSystem<TFinalAuthInfo, TUserInfo>.UserInfoType => _userType;

        /// <summary>
        /// Gets the associated user info type.
        /// </summary>
        public StdUserInfoType<TUserInfo> UserInfoType => _userType;

        /// <summary>
        /// Gets the non authentication information: it has a <see cref="IAuthenticationInfo.Level"/> equals to
        /// <see cref="AuthLevel.None"/> and is semantically the same as a null reference (all authentication
        /// information with a None level are equivalent).
        /// Use <see cref="AuthenticationExtensions.IsNullOrNone{TUserInfo}(IAuthenticationInfo{TUserInfo})">IsNullOrNone</see> to 
        /// easily test both cases.
        /// </summary>
        public TFinalAuthInfo None => _none.Value;

        protected abstract TFinalAuthInfo CreateNone();

        /// <summary>
        /// Reads a <see cref="ClaimsIdentity"/> that has been previously created by <see cref="ToClaimsIdentity(TFinalAuthInfo, bool)"/>.
        /// <para>
        /// This returns null if <paramref name="id"/> is null or the <see cref="ClaimsIdentity.AuthenticationType"/>
        /// is not <see cref="ClaimAuthenticationType"/> or <see cref="ClaimAuthenticationTypeSimple"/>.
        /// </para>
        /// <para>
        /// Note that <see cref="AuthLevelKeyType"/> claim is ignored: the final level depends
        /// on <see cref="ExpirationKeyType"/> and <see cref="CriticalExpirationKeyType"/>.
        /// </para>
        /// <para>
        /// This method should not be overridden, it is virtual for the sake of openness.
        /// Extra data must be handled by <see cref="AuthenticationInfoFromClaimsIdentity"/>. 
        /// </para>
        /// </summary>
        /// <param name="id">The claims identity.</param>
        /// <returns>A new authentication object.</returns>
        public virtual TFinalAuthInfo FromClaimsIdentity( ClaimsIdentity id )
        {
            if( id == null
                || (id.AuthenticationType != ClaimAuthenticationType && id.AuthenticationType != ClaimAuthenticationTypeSimple) )
            {
                return null;
            }
            TUserInfo actualUser = null;
            TUserInfo user = _userType.FromClaims( id.Claims );
            IEnumerable<Claim> actualActorClaims = id.Claims;
            if( id.Actor != null )
            {
                actualUser = _userType.FromClaims( id.Actor.Claims );
                actualActorClaims = id.Actor.Claims;
            }
            string exp = actualActorClaims.FirstOrDefault( c => c.Type == ExpirationKeyType )?.Value;
            var expires = exp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( exp ) ) : null;
            string criticalExp = actualActorClaims.FirstOrDefault( c => c.Type == CriticalExpirationKeyType )?.Value;
            var criticalExpires = criticalExp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( criticalExp ) ) : null;
            return AuthenticationInfoFromClaimsIdentity( actualUser, user, expires, criticalExpires, id, actualActorClaims );
        }

        /// <summary>
        /// Implements ultimate step of <see cref="FromClaimsIdentity(ClaimsIdentity)"/>.
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
        protected abstract TFinalAuthInfo AuthenticationInfoFromClaimsIdentity(
            TUserInfo actualUser,
            TUserInfo user,
            DateTime? expires,
            DateTime? criticalExpires,
            ClaimsIdentity id,
            IEnumerable<Claim> actualActorClaims );

        /// <summary>
        /// Implements <see cref="IAuthenticationTypeSystem.ToJObject(IAuthenticationInfo)"/>.
        /// </summary>
        /// <param name="info">The authentication information.</param>
        /// <returns>Authentication information as a JObject.</returns>
        public virtual JObject ToJObject( TFinalAuthInfo info )
        {
            if( info.IsNullOrNone() ) return null;
            var o = new JObject();
            o.Add( new JProperty( UserKeyType, _userType.ToJObject( info.UnsafeUser ) ) );
            if( info.IsImpersonated ) o.Add( new JProperty( ActualUserKeyType, _userType.ToJObject( info.UnsafeActualUser ) ) );
            if( info.Expires.HasValue ) o.Add( new JProperty( ExpirationKeyType, info.Expires ) );
            if( info.CriticalExpires.HasValue ) o.Add( new JProperty( CriticalExpirationKeyType, info.CriticalExpires ) );
            return o;
        }

        /// <summary>
        /// Creates a <typeparamref name="TAuthInfo"/> from a JObject (or null if <paramref name="o"/> is null).
        /// <para>
        /// This default implementation handles error (by always throwing a <see cref="InvalidDataException"/>)
        /// and extracts standard fields named <see cref="UserKeyType"/>, <see cref="ActualUserKeyType"/>,
        /// <see cref="ExpirationKeyType"/> and <see cref="CriticalExpirationKeyType"/>, and then calls
        /// the extension point <see cref="AuthenticationInfoFromJObject"/>.
        /// </para>
        /// <para>
        /// This method should not be overridden, it is virtual for the sake of openness.
        /// Extra data must be handled by <see cref="AuthenticationInfoFromJObject"/>. 
        /// </para>
        /// </summary>
        /// <param name="o">The JSON object.</param>
        /// <returns>The extracted authentication info or null if <paramref name="o"/> is null.</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the object is not in the expected format.
        /// </exception>
        public virtual TFinalAuthInfo FromJObject( JObject o )
        {
            if( o == null ) return null;
            try
            {
                var user = _userType.FromJObject( (JObject)o[UserKeyType] );
                var actualUser = _userType.FromJObject( (JObject)o[ActualUserKeyType] );
                var expires = (DateTime?)o[ExpirationKeyType];
                var criticalExpires = (DateTime?)o[CriticalExpirationKeyType];
                return AuthenticationInfoFromJObject( actualUser, user, expires, criticalExpires, o );
            }
            catch( Exception ex )
            {
                throw new InvalidDataException( o.ToString( Formatting.None ), ex );
            }
        }

        /// <summary>
        /// Implements the ultimate step of <see cref="FromJObject(JObject)"/>.
        /// Must throw <see cref="InvalidDataException"/> if the parameter o is not valid.
        /// </summary>
        /// <param name="actualUser">The actual user already read.</param>
        /// <param name="user">The user already read.</param>
        /// <param name="expires">The expiration already read.</param>
        /// <param name="criticalExpires">The critical expiration already read.</param>
        /// <param name="o">The JObject that may be used to extract any extra field.</param>
        /// <returns>The authentication information.</returns>
        protected abstract TFinalAuthInfo AuthenticationInfoFromJObject(
            TUserInfo actualUser,
            TUserInfo user,
            DateTime? expires,
            DateTime? criticalExpires,
            JObject o );

        /// <summary>
        /// Implements <see cref="IAuthenticationTypeSystem.ToClaimsIdentity"/>.
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
        public virtual ClaimsIdentity ToClaimsIdentity( TFinalAuthInfo info, bool userInfoOnly )
        {
            if( info.IsNullOrNone() ) return null;
            if( !(info is TAuthInfo tInfo) ) throw new ArgumentException( $"Must be a '{typeof( TAuthInfo ).FullName}'.", nameof( info ) );
            ClaimsIdentity id = userInfoOnly
                                    ? new ClaimsIdentity( _userType.ToClaims( info.User ), ClaimAuthenticationTypeSimple, UserNameKeyType, null )
                                    : new ClaimsIdentity( _userType.ToClaims( info.UnsafeUser ), ClaimAuthenticationType, UserNameKeyType, null );
            ClaimsIdentity propertyBearer = id;
            if( !userInfoOnly )
            {
                if( info.IsImpersonated )
                {
                    id.Actor = propertyBearer = new ClaimsIdentity( _userType.ToClaims( info.UnsafeActualUser ), ClaimAuthenticationType, UserNameKeyType, null );
                }
                propertyBearer.AddClaim( new Claim( AuthLevelKeyType, info.Level.ToString() ) );
            }
            if( info.Expires.HasValue ) propertyBearer.AddClaim( new Claim( ExpirationKeyType, info.Expires.Value.ToUnixTimeSeconds().ToString() ) );
            if( info.CriticalExpires.HasValue ) propertyBearer.AddClaim( new Claim( CriticalExpirationKeyType, info.CriticalExpires.Value.ToUnixTimeSeconds().ToString() ) );
            return id;
        }

        /// <summary>
        /// Writes the authentication information in binary format.
        /// <para>
        /// This method should not be overridden, it is virtual for the sake of openness.
        /// Extra data must be handled by <see cref="WriteAuthenticationInfoRemainder"/>. 
        /// </para>
        /// </summary>
        /// <param name="w">The binary writer (must not be null).</param>
        /// <param name="info">The user info to write. Can be null.</param>
        public virtual void Write( BinaryWriter w, TFinalAuthInfo info )
        {
            if( w == null ) throw new ArgumentNullException( nameof( w ) );
            if( info.IsNullOrNone() ) w.Write( 0 );
            else
            {
                if( !(info is TAuthInfo tInfo) ) throw new ArgumentException( $"Must be a '{typeof( TAuthInfo ).FullName}'.", nameof( info ) );
                w.Write( 1 );
                int flag = 0;
                if( info.IsImpersonated ) flag |= 1;
                if( info.Expires.HasValue ) flag |= 2;
                if( info.CriticalExpires.HasValue ) flag |= 4;
                w.Write( (byte)flag );
                _userType.Write( w, info.UnsafeUser );
                if( info.IsImpersonated ) _userType.Write( w, info.UnsafeActualUser );
                if( info.Expires.HasValue ) w.Write( info.Expires.Value.ToBinary() );
                if( info.CriticalExpires.HasValue ) w.Write( info.CriticalExpires.Value.ToBinary() );
                WriteAuthenticationInfoRemainder( w, info );
            }
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationTypeSystem.Write(BinaryWriter, IAuthenticationInfo)"/>.
        /// Only extra properties to <see cref="IAuthenticationInfo"/> must be written.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The authentication info to write. Can be null.</param>
        protected abstract void WriteAuthenticationInfoRemainder( BinaryWriter w, TAuthInfo info );

        /// <summary>
        /// Creates a <typeparamref name="TAuthInfo"/> from a binary reader.
        /// This default implementation reads the basic <see cref="IAuthenticationInfo"/> data
        /// and then calls the extension point <see cref="ReadAuthenticationInfoRemainder"/>.
        /// <para>
        /// This method should not be overridden, it is virtual for the sake of openness.
        /// </para>
        /// </summary>
        /// <param name="r">The binary reader (must not be null).</param>
        /// <returns>A new authentication object.</returns>
        public virtual TFinalAuthInfo Read( BinaryReader r )
        {
            if( r == null ) throw new ArgumentNullException( nameof( r ) );
            try
            {
                int version = r.ReadInt32();
                if( version == 0 ) return null;
                int flags = r.ReadByte();
                var user = _userType.Read( r );
                TUserInfo actualUser = null;
                DateTime? expires = null;
                DateTime? criticalExpires = null;
                if( (flags & 1) != 0 ) actualUser = _userType.Read( r );
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
        /// Implements last step of <see cref="Read(BinaryReader)"/>.
        /// Basic fields of <see cref="IAuthenticationInfo"/> are already read.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <param name="actualUser">Already read actual user.</param>
        /// <param name="user">Already read user.</param>
        /// <param name="expires">Already read expires.</param>
        /// <param name="criticalExpires">Already read critical expires.</param>
        /// <returns>The authentication info.</returns>
        protected abstract TFinalAuthInfo ReadAuthenticationInfoRemainder( BinaryReader r, TUserInfo actualUser, TUserInfo user, DateTime? expires, DateTime? criticalExpires );


    }
}
