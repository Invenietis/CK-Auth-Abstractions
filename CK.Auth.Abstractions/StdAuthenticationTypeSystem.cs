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
    /// implements <see cref="IAuthenticationInfoType"/> and <see cref="IUserInfoType"/>).
    /// </summary>
    public class StdAuthenticationTypeSystem : IAuthenticationTypeSystem, IAuthenticationInfoType, IUserInfoType
    {
        Lazy<IUserInfo> _anonymous;
        Lazy<IAuthenticationInfo> _none;
        string _authenticationType = "CKA";
        static readonly IUserProviderInfo[] _emptyProviders = new IUserProviderInfo[0];



        /// <summary>
        /// Gets or sets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// Defaults to "CKA".
        /// </summary>
        public string AuthenticationType { get => _authenticationType; protected set => _authenticationType = value; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
        /// when exporting only the saf user claims and enforced by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
        /// Always equal to "<see cref="AuthenticationType"/>-S" (defaults to "CKA-S").
        /// </summary>
        public string AuthenticationTypeSimple => AuthenticationType + "-S";

        /// <summary>
        /// The name of the <see cref="IUserInfo.DisplayName"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string DisplayNameKeyType = "name";

        /// <summary>
        /// The name of the <see cref="IUserInfo.ActorId"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string ActorIdKeyType = "id";

        /// <summary>
        /// The name of the <see cref="IUserInfo.Providers"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
        /// </summary>
        public const string ProvidersKeyType = "providers";

        /// <summary>
        /// The name of the <see cref="IAuthenticationInfo.Level"/> for the <see cref="Claim.Type"/>
        /// and JObject property name.
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
            _anonymous = new Lazy<IUserInfo>(CreateAnonymous, LazyThreadSafetyMode.PublicationOnly);
            _none = new Lazy<IAuthenticationInfo>(() => CreateAuthenticationInfo( _anonymous.Value, null ), LazyThreadSafetyMode.PublicationOnly);
        }

        /// <summary>
        /// Gets the <see cref="IUserInfoType"/> type manager (actually, this object implements it).
        /// </summary>
        public IUserInfoType UserInfo => this;

        /// <summary>
        /// Gets the <see cref="IAuthenticationInfoType"/> type manager (actually, this object implements it).
        /// </summary>
        public IAuthenticationInfoType AuthenticationInfo => this;

        #region IUserInfo
        IUserInfo IUserInfoType.Anonymous => _anonymous.Value;

        IUserInfo IUserInfoType.FromClaims(IEnumerable<Claim> claims)
        {
            if (claims == null) return null;
            int actorId = 0;
            string displayName = null;
            IUserProviderInfo[] providers = null;
            foreach (var c in claims)
            {
                if (c.Type == ActorIdKeyType)
                {
                    actorId = int.Parse(c.Value);
                    if (actorId == 0) return _anonymous.Value;
                }
                if (c.Type == DisplayNameKeyType) displayName = c.Value;
                if (c.Type == ProvidersKeyType) providers = FromProvidersJArray(JArray.Parse(c.Value));
                if (actorId != 0 && displayName != null && providers != null) break;
            }
            return UserInfoFromClaims(actorId, displayName, providers, claims);
        }

        IUserInfo IUserInfoType.FromJObject(JObject o) => UserInfoFromJObject(o);

        List<Claim> IUserInfoType.ToClaims(IUserInfo info) => UserInfoToClaims(info);

        JObject IUserInfoType.ToJObject(IUserInfo info) => UserInfoToJObject(info);

        void IUserInfoType.Write(BinaryWriter w, IUserInfo info)
        {
            if (info == null) w.Write(0);
            else w.Write(1);
            w.Write(info.ActorId);
            w.Write(info.DisplayName);
            w.Write(info.Providers.Count);
            foreach (var p in info.Providers)
            {
                w.Write(p.Name);
                w.Write(p.LastUsed.ToBinary());
            }
            WriteUserInfoRemainder(w, info);
        }


        IUserInfo IUserInfoType.Read(BinaryReader r)
        {
            int version = r.ReadInt32();
            if (version == 0) return null;
            int actorId = r.ReadInt32();
            string name = r.ReadString();
            int providerCount = r.ReadInt32();
            IUserProviderInfo[] providers = _emptyProviders;
            if (providerCount > 0)
            {
                providers = new IUserProviderInfo[providerCount];
                for(int i = 0; i < providerCount; ++i)
                {
                    providers[i] = new StdUserProviderInfo(r.ReadString(), DateTime.FromBinary(r.ReadInt64()));
                }
            }
            return ReadUserInfoRemainder(r, actorId, name, providers);
        }

        /// <summary>
        /// Must create the anonymous object.
        /// </summary>
        /// <returns>The anonymous object.</returns>
        protected virtual IUserInfo CreateAnonymous() => new StdUserInfo(0, null, null);

        /// <summary>
        /// Implements <see cref="IUserInfoType.ToJObject(IUserInfo)"/>.
        /// </summary>
        /// <param name="info">The user information.</param>
        /// <returns>User information as a JObject.</returns>
        protected virtual JObject UserInfoToJObject(IUserInfo info)
        {
            if (info == null) return null;
            return new JObject(
                    new JProperty(ActorIdKeyType, info.ActorId),
                    new JProperty(DisplayNameKeyType, info.DisplayName),
                    new JProperty(ProvidersKeyType, ToProvidersJArray(info.Providers)));
        }

        /// <summary>
        /// Helpers to get a JArray from <see cref="IUserInfo.Providers"/>.
        /// </summary>
        /// <param name="providers">Providers.</param>
        /// <returns>A JArray of {name:..., lastUsed:...} objects.</returns>
        protected JArray ToProvidersJArray(IEnumerable<IUserProviderInfo> providers)
                    => new JArray(providers.Select(
                                    p => new JObject(new JProperty("name", p.Name), new JProperty("lastUsed", p.LastUsed))));

        /// <summary>
        /// Helpers to get providers from a JArray of {name:..., lastUsed:...} objects..
        /// </summary>
        /// <param name="a">Jarray to convert.</param>
        /// <returns>An array of providers.</returns>
        protected IUserProviderInfo[] FromProvidersJArray(JArray a)
                    => a.Select(p => new StdUserProviderInfo((string)p["name"], (DateTime)p["lastUsed"])).ToArray();

        /// <summary>
        /// Implements <see cref="IUserInfoType.FromJObject(JObject)"/>.
        /// </summary>
        /// <param name="o">The JObject.</param>
        /// <returns>The user information.</returns>
        protected virtual IUserInfo UserInfoFromJObject(JObject o)
        {
            if (o == null) return null;
            var actorId = (int)o[ActorIdKeyType];
            if (actorId == 0) return _anonymous.Value;
            var displayName = (string)o[DisplayNameKeyType];
            var providers = o[ProvidersKeyType].Select(p => new StdUserProviderInfo((string)p["name"], (DateTime)p["lastUsed"])).ToArray();
            return new StdUserInfo(actorId, displayName, providers);
        }

        /// <summary>
        /// Implements <see cref="IUserInfoType.ToClaims(IUserInfo)"/> by returning 
        /// three claims (<see cref="DisplayNameKeyType"/>, <see cref="ActorIdKeyType"/> and <see cref="ProvidersKeyType"/>)
        /// in the list.
        /// </summary>
        /// <param name="info">The user information.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> object.</returns>
        protected virtual List<Claim> UserInfoToClaims(IUserInfo info)
        {
            if (info == null) return null;
            var list = new List<Claim>();
            list.Add(new Claim(DisplayNameKeyType, info.DisplayName));
            list.Add(new Claim(ActorIdKeyType, info.ActorId.ToString()));
            list.Add(new Claim(ProvidersKeyType, ToProvidersJArray(info.Providers).ToString(Formatting.None)));
            return list;
        }

        /// <summary>
        /// Implements <see cref="IUserInfoType.FromClaims(IEnumerable{Claim})"/>.
        /// </summary>
        /// <param name="actorId">The value read from <see cref="ActorIdKeyType"/> claim.</param>
        /// <param name="displayName">The value read from <see cref="DisplayNameKeyType"/> claim.</param>
        /// <param name="providers">The Array read from <see cref="ProvidersKeyType"/> claim.</param>
        /// <param name="claims">All the Claims (including the 3 already extracted ones).</param>
        /// <returns>The user information.</returns>
        protected virtual IUserInfo UserInfoFromClaims(int actorId, string displayName, IUserProviderInfo[] providers, IEnumerable<Claim> claims)
        {
            return new StdUserInfo(actorId, displayName, providers);
        }

        /// <summary>
        /// Implements <see cref="IUserInfoType.Write(BinaryWriter, IUserInfo)"/>.
        /// Only extra fields to <see cref="IUserInfo"/> should be written here.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The user info to write.</param>
        protected virtual void WriteUserInfoRemainder(BinaryWriter w, IUserInfo info)
        {
        }

        /// <summary>
        /// Implements <see cref="IUserInfoType.Read(BinaryReader)"/>.
        /// Basic fields of <see cref="IUserInfo"/> are already read.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <param name="actorId">Already read actor identifier.</param>
        /// <param name="name">Already read display name.</param>
        /// <param name="providers">Already read providers.</param>
        /// <returns>The user info.</returns>
        protected virtual IUserInfo ReadUserInfoRemainder(BinaryReader r, int actorId, string name, IUserProviderInfo[] providers)
        {
            return new StdUserInfo(actorId, name, providers);
        }

        #endregion

        #region IAuthenticationInfo

        IAuthenticationInfo IAuthenticationInfoType.None => _none.Value;

        string IAuthenticationInfoType.AuthenticationType => _authenticationType;

        IAuthenticationInfo IAuthenticationInfoType.Create(IUserInfo user, DateTime? expires, DateTime? criticalExpires) => CreateAuthenticationInfo(user, expires, criticalExpires);

        IAuthenticationInfo IAuthenticationInfoType.FromClaimsIdentity( ClaimsIdentity id )
        {
            if (id == null
                || (id.AuthenticationType != AuthenticationType && id.AuthenticationType != AuthenticationTypeSimple))
            {
                return null;
            }
            IUserInfo actualUser = null;
            IUserInfo user = UserInfo.FromClaims(id.Claims);
            IEnumerable<Claim> actualActorClaims = id.Claims;
            if (id.Actor != null)
            {
                actualUser = UserInfo.FromClaims(id.Actor.Claims);
                actualActorClaims = id.Actor.Claims;
            }
            string exp = actualActorClaims.FirstOrDefault(c => c.Type == ExpirationKeyType)?.Value;
            var expires = exp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds(long.Parse(exp)) : null;
            string criticalExp = actualActorClaims.FirstOrDefault(c => c.Type == CriticalExpirationKeyType)?.Value;
            var criticalExpires = criticalExp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds(long.Parse(criticalExp)) : null;
            return AuthenticationInfoFromClaimsIdentity(actualUser, user, expires, criticalExpires, id, actualActorClaims);
        }

        IAuthenticationInfo IAuthenticationInfoType.FromJObject( JObject o ) => AuthenticationInfoFromJObject( o );

        ClaimsIdentity IAuthenticationInfoType.ToClaimsIdentity( IAuthenticationInfo info, bool userInfoOnly ) => AuthenticationInfoToClaimsIdentity( info, userInfoOnly );

        JObject IAuthenticationInfoType.ToJObject( IAuthenticationInfo info ) => AuthenticationInfoToJObject( info );

        void IAuthenticationInfoType.Write(BinaryWriter w, IAuthenticationInfo info)
        {
            if (info.IsNullOrNone()) w.Write(0);
            else w.Write(1);
            int flag = 0;
            if (info.IsImpersonated) flag |= 1;
            if (info.Expires.HasValue) flag |= 2;
            if (info.CriticalExpires.HasValue) flag |= 4;
            w.Write((byte)flag);
            UserInfo.Write(w, info.UnsafeUser);
            if (info.IsImpersonated) UserInfo.Write(w, info.UnsafeActualUser);
            if (info.Expires.HasValue) w.Write(info.Expires.Value.ToBinary());
            if (info.CriticalExpires.HasValue) w.Write(info.CriticalExpires.Value.ToBinary());
            WriteAuthenticationInfoRemainder(w, info);
        }

        IAuthenticationInfo IAuthenticationInfoType.Read(BinaryReader r)
        {
            int version = r.ReadInt32();
            if (version == 0) return null;
            int flags = r.ReadByte();
            IUserInfo user = UserInfo.Read(r);
            IUserInfo actualUser = null;
            DateTime? expires = null;
            DateTime? criticalExpires = null;
            if ((flags & 1) != 0) actualUser = UserInfo.Read(r);
            if ((flags & 2) != 0) expires = DateTime.FromBinary(r.ReadInt64());
            if ((flags & 4) != 0) criticalExpires = DateTime.FromBinary(r.ReadInt64());
            return ReadAuthenticationInfoRemainder(r, actualUser, user, expires, criticalExpires);
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.Create"/>.
        /// </summary>
        /// <param name="user">The unsafe user information.</param>
        /// <param name="expires">When null or already expired, Level is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Optional critical expiration.</param>
        /// <returns>The unsafe authentication information.</returns>
        protected virtual IAuthenticationInfo CreateAuthenticationInfo(IUserInfo user, DateTime? expires, DateTime? criticalExpires = null)
        {
            return user == null ? _none.Value : new StdAuthenticationInfo(this, user, expires, criticalExpires);
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
            var user = UserInfoFromJObject( (JObject)o[UserKeyType] );
            var actualUser = UserInfoFromJObject( (JObject)o[ActualUserKeyType] );
            var expires = (DateTime?)o[ExpirationKeyType];
            var criticalExpires = (DateTime?)o[CriticalExpirationKeyType];
            return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires );
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>.
        /// It uses <see cref="AuthenticationType"/> as the <see cref="ClaimsIdentity.AuthenticationType"/>
        /// and the <see cref="ClaimsIdentity.Actor"/> for impersonation.
        /// </summary>
        /// <param name="info">The authentication information.</param>
        /// <param name="userInfoOnly">
        /// True to add (safe) user claims and ignore any impersonation.
        /// False to add unsafe user claims, a <see cref="AuthLevelKeyType"/> claim for the authentication level,
        /// the expirations if they exist and handle impersonation thanks to the <see cref="ClaimsIdentity.Actor"/>. 
        /// </param>
        /// <returns>Authentication information as a claim identity.</returns>
        protected virtual ClaimsIdentity AuthenticationInfoToClaimsIdentity(IAuthenticationInfo info, bool userInfoOnly)
        {
            if (info.IsNullOrNone()) return null;
            ClaimsIdentity id = userInfoOnly
                                    ? new ClaimsIdentity(UserInfoToClaims(info.User), AuthenticationTypeSimple, DisplayNameKeyType, null)
                                    : new ClaimsIdentity(UserInfoToClaims(info.UnsafeUser), AuthenticationType, DisplayNameKeyType, null);
            ClaimsIdentity propertyBearer = id;
            if (!userInfoOnly)
            {
                if (info.IsImpersonated)
                {
                    id.Actor = propertyBearer = new ClaimsIdentity(UserInfoToClaims(info.UnsafeActualUser), AuthenticationType, DisplayNameKeyType, null);
                }
                propertyBearer.AddClaim(new Claim(AuthLevelKeyType, info.Level.ToString()));
            }
            if (info.Expires.HasValue) propertyBearer.AddClaim(new Claim(ExpirationKeyType, info.Expires.Value.ToUnixTimeSeconds().ToString()));
            if (info.CriticalExpires.HasValue) propertyBearer.AddClaim(new Claim(CriticalExpirationKeyType, info.CriticalExpires.Value.ToUnixTimeSeconds().ToString()));
            return id;
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.FromClaimsIdentity(ClaimsIdentity)"/>.
        /// Note that <see cref="AuthLevelKeyType"/> claim is ignored: the final level is depends
        /// on <see cref="ExpirationKeyType"/> and <see cref="CriticalExpirationKeyType"/>.
        /// </summary>
        /// <param name="actualUser">The actual user (from <see cref="ClaimsIdentity.Actor"/>).</param>
        /// <param name="user">The user information.</param>
        /// <param name="expires">The expiration.</param>
        /// <param name="criticalExpires">The critical expiration.</param>
        /// <param name="id">The claims identity.</param>
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
            return new StdAuthenticationInfo(this, actualUser, user, expires, criticalExpires);
        }

        /// <summary>
        /// Implements <see cref="IAuthenticationInfoType.Write(BinaryWriter, IAuthenticationInfo)"/>.
        /// Only extra properties to <see cref="IAuthenticationInfo"/> must be written.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The authentication info to write. Can be null.</param>
        protected virtual void WriteAuthenticationInfoRemainder(BinaryWriter w, IAuthenticationInfo info)
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
        private IAuthenticationInfo ReadAuthenticationInfoRemainder(BinaryReader r, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires)
        {
            return new StdAuthenticationInfo(this, actualUser, user, expires, criticalExpires);
        }

        #endregion

    }
}
