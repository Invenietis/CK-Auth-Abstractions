using CK.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading;

namespace CK.Auth;

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
    static readonly IUserSchemeInfo[] _emptySchemes = new IUserSchemeInfo[0];


    /// <summary>
    /// Gets or sets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
    /// and checked back by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
    /// Defaults to "CKA".
    /// </summary>
    public string ClaimAuthenticationType { get => _authenticationType; protected set => _authenticationType = value; }

    /// <summary>
    /// Gets the <see cref="ClaimsIdentity.AuthenticationType"/> used by <see cref="IAuthenticationInfoType.ToClaimsIdentity"/>
    /// when exporting only the safe user claims and checked back by <see cref="IAuthenticationInfoType.FromClaimsIdentity"/>.
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
    /// The name of the <see cref="IAuthenticationInfo.DeviceId"/> for the JObject property name.
    /// </summary>
    public const string DeviceIdKeyType = "device";

    /// <summary>
    /// Initializes a new <see cref="StdAuthenticationTypeSystem"/>.
    /// </summary>
    public StdAuthenticationTypeSystem()
    {
        _anonymous = new Lazy<IUserInfo>( CreateAnonymous, LazyThreadSafetyMode.PublicationOnly );
        _none = new Lazy<IAuthenticationInfo>( () => CreateAuthenticationInfo( _anonymous.Value, null, null, null ), LazyThreadSafetyMode.PublicationOnly );
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

    /// <summary>
    /// Creates a new <see cref="IUserInfo"/>.
    /// </summary>
    /// <param name="userId">The user identifier.</param>
    /// <param name="userName">The user name. Can be null or empty if and only if <paramref name="userId"/> is 0.</param>
    /// <param name="schemes">The schemes list.</param>
    public virtual IUserInfo Create( int userId, string? userName, IReadOnlyList<IUserSchemeInfo>? schemes = null )
    {
        return new StdUserInfo( userId, userName, schemes );
    }


    IUserInfo? IUserInfoType.FromClaims( IEnumerable<Claim>? claims )
    {
        if( claims == null ) return null;
        int userId = 0;
        string? userName = null;
        IUserSchemeInfo[]? schemes = null;
        foreach( var c in claims )
        {
            if( c.Type == UserIdKeyType )
            {
                userId = int.Parse( c.Value );
                if( userId == 0 ) return _anonymous.Value;
            }
            if( c.Type == UserNameKeyType ) userName = c.Value;
            if( c.Type == SchemesKeyType ) schemes = FromSchemesJArray( JArray.Parse( c.Value ) );
            if( userId != 0 && userName != null && schemes != null ) break;
        }
        return UserInfoFromClaims( userId, userName, schemes, claims );
    }

    IUserInfo? IUserInfoType.FromJObject( JObject? o ) => UserInfoFromJObject( o );

    List<Claim>? IUserInfoType.ToClaims( IUserInfo? info ) => UserInfoToClaims( info );

    JObject? IUserInfoType.ToJObject( IUserInfo? info ) => UserInfoToJObject( info );

    void IUserInfoType.Write( BinaryWriter w, IUserInfo? info )
    {
        if( info == null ) w.Write( 0 );
        else
        {
            w.Write( 1 );
            w.Write( info.UserId );
            w.Write( info.UserName );
            w.Write( info.Schemes.Count );
            foreach( var p in info.Schemes )
            {
                w.Write( p.Name );
                w.Write( p.LastUsed.ToBinary() );
            }
            WriteUserInfoRemainder( w, info );
        }
    }

    IUserInfo? IUserInfoType.Read( BinaryReader r )
    {
        if( r == null ) throw new ArgumentNullException( nameof( r ) );
        try
        {
            int version = r.ReadInt32();
            if( version == 0 ) return null;
            int userId = r.ReadInt32();
            string name = r.ReadString();
            int schemeCount = r.ReadInt32();
            IUserSchemeInfo[] schemes = _emptySchemes;
            if( schemeCount > 0 )
            {
                schemes = new IUserSchemeInfo[schemeCount];
                for( int i = 0; i < schemeCount; ++i )
                {
                    schemes[i] = new StdUserSchemeInfo( r.ReadString(), DateTime.FromBinary( r.ReadInt64() ) );
                }
            }
            return ReadUserInfoRemainder( r, userId, name, schemes );
        }
        catch( Exception ex )
        {
            throw new InvalidDataException( "Invalid binary format.", ex );
        }
    }

    /// <summary>
    /// Must create the anonymous object.
    /// </summary>
    /// <returns>The anonymous object.</returns>
    protected virtual IUserInfo CreateAnonymous() => new StdUserInfo( 0, null, null );

    /// <summary>
    /// Implements <see cref="IUserInfoType.ToJObject(IUserInfo)"/>.
    /// </summary>
    /// <param name="info">The user information.</param>
    /// <returns>User information as a JObject.</returns>
    protected virtual JObject? UserInfoToJObject( IUserInfo? info )
    {
        if( info == null ) return null;
        return new JObject(
                new JProperty( UserIdKeyType, info.UserId ),
                new JProperty( UserNameKeyType, info.UserName ),
                new JProperty( SchemesKeyType, ToSchemesJArray( info.Schemes ) ) );
    }

    /// <summary>
    /// Helpers to get a JArray from <see cref="IUserInfo.Schemes"/>.
    /// </summary>
    /// <param name="schemes">The schemes.</param>
    /// <returns>A JArray of {name:..., lastUsed:...} objects.</returns>
    protected virtual JArray ToSchemesJArray( IEnumerable<IUserSchemeInfo> schemes )
                => new JArray( schemes.Select(
                                p => new JObject( new JProperty( "name", p.Name ), new JProperty( "lastUsed", p.LastUsed ) ) ) );

    /// <summary>
    /// Helpers to get providers from a JArray of {name:..., lastUsed:...} objects..
    /// </summary>
    /// <param name="a">Jarray to convert.</param>
    /// <returns>An array of providers.</returns>
    protected virtual IUserSchemeInfo[] FromSchemesJArray( JArray a )
                => a.Select( p => new StdUserSchemeInfo( (string)p["name"]!, (DateTime)p["lastUsed"]! ) ).ToArray();

    /// <summary>
    /// Implements <see cref="IUserInfoType.FromJObject(JObject)"/>.
    /// </summary>
    /// <param name="o">The JObject.</param>
    /// <returns>The user information.</returns>
    protected virtual IUserInfo? UserInfoFromJObject( JObject? o )
    {
        if( o == null ) return null;
        try
        {
            var userId = (int?)o[UserIdKeyType] ?? 0;
            if( userId == 0 ) return _anonymous.Value;
            var userName = (string?)o[UserNameKeyType];
            // providers was the previous name: gracefully handles it here.
            JToken? t = o[SchemesKeyType] ?? o["providers"];
            var schemes = t != null
                            // StdUserSchemeInfo will throw if "name" or "lastUsed" are not found.
                            ? t.Select( p => new StdUserSchemeInfo( (string)p["name"]!, (DateTime)p["lastUsed"]! ) ).ToArray()
                            : null;
            return new StdUserInfo( userId, userName, schemes );
        }
        catch( Exception ex )
        {
            throw new InvalidDataException( o.ToString( Formatting.None ), ex );
        }
    }

    /// <summary>
    /// Implements <see cref="IUserInfoType.ToClaims(IUserInfo)"/> by returning 
    /// three claims (<see cref="UserNameKeyType"/>, <see cref="UserIdKeyType"/> and <see cref="SchemesKeyType"/>)
    /// in the list.
    /// </summary>
    /// <param name="info">The user information.</param>
    /// <returns>A <see cref="ClaimsIdentity"/> object or null if info is null.</returns>
    [return: NotNullIfNotNull( "info" )]
    protected virtual List<Claim>? UserInfoToClaims( IUserInfo? info )
    {
        if( info == null ) return null;
        var list = new List<Claim>();
        list.Add( new Claim( UserNameKeyType, info.UserName ) );
        list.Add( new Claim( UserIdKeyType, info.UserId.ToString() ) );
        list.Add( new Claim( SchemesKeyType, ToSchemesJArray( info.Schemes ).ToString( Formatting.None ) ) );
        return list;
    }

    /// <summary>
    /// Implements <see cref="IUserInfoType.FromClaims(IEnumerable{Claim})"/>.
    /// </summary>
    /// <param name="userId">The value read from <see cref="UserIdKeyType"/> claim.</param>
    /// <param name="userName">The value read from <see cref="UserNameKeyType"/> claim.</param>
    /// <param name="schemes">The Array read from <see cref="SchemesKeyType"/> claim.</param>
    /// <param name="claims">All the Claims (including the 3 already extracted ones).</param>
    /// <returns>The user information.</returns>
    protected virtual IUserInfo UserInfoFromClaims( int userId, string? userName, IUserSchemeInfo[]? schemes, IEnumerable<Claim> claims )
    {
        return new StdUserInfo( userId, userName, schemes );
    }

    /// <summary>
    /// Implements <see cref="IUserInfoType.Write(BinaryWriter, IUserInfo)"/>.
    /// Only extra fields to <see cref="IUserInfo"/> should be written here.
    /// </summary>
    /// <param name="w">The binary writer.</param>
    /// <param name="info">The user info to write.</param>
    protected virtual void WriteUserInfoRemainder( BinaryWriter w, IUserInfo info )
    {
    }

    /// <summary>
    /// Implements <see cref="IUserInfoType.Read(BinaryReader)"/>.
    /// Basic fields of <see cref="IUserInfo"/> are already read.
    /// </summary>
    /// <param name="r">The binary reader.</param>
    /// <param name="userId">Already read user identifier.</param>
    /// <param name="name">Already read user name.</param>
    /// <param name="schemes">Already read providers.</param>
    /// <returns>The user info.</returns>
    protected virtual IUserInfo ReadUserInfoRemainder( BinaryReader r, int userId, string name, IUserSchemeInfo[] schemes )
    {
        return new StdUserInfo( userId, name, schemes );
    }

    #endregion

    #region IAuthenticationInfo

    IAuthenticationInfo IAuthenticationInfoType.None => _none.Value;

    IAuthenticationInfo IAmbientServiceDefaultProvider<IAuthenticationInfo>.Default => _none.Value;

    IAuthenticationInfo IAuthenticationInfoType.Create( IUserInfo? user, DateTime? expires, DateTime? criticalExpires, string? deviceId ) => CreateAuthenticationInfo( user, expires, criticalExpires, deviceId );

    IAuthenticationInfo? IAuthenticationInfoType.FromClaimsIdentity( ClaimsIdentity? id )
    {
        if( id == null
            || (id.AuthenticationType != ClaimAuthenticationType && id.AuthenticationType != ClaimAuthenticationTypeSimple) )
        {
            return null;
        }
        IUserInfo? actualUser = null;
        IUserInfo? user = UserInfo.FromClaims( id.Claims );
        IEnumerable<Claim> actualActorClaims = id.Claims;
        if( id.Actor != null )
        {
            actualUser = UserInfo.FromClaims( id.Actor.Claims );
            actualActorClaims = id.Actor.Claims;
        }
        string? exp = actualActorClaims.FirstOrDefault( c => c.Type == ExpirationKeyType )?.Value;
        var expires = exp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( exp ) ) : null;

        string? criticalExp = actualActorClaims.FirstOrDefault( c => c.Type == CriticalExpirationKeyType )?.Value;
        var criticalExpires = criticalExp != null ? (DateTime?)DateTimeExtensions.UnixEpoch.AddSeconds( long.Parse( criticalExp ) ) : null;

        string? deviceId = actualActorClaims.FirstOrDefault( c => c.Type == DeviceIdKeyType )?.Value;

        return AuthenticationInfoFromClaimsIdentity( actualUser, user, expires, criticalExpires, deviceId, id, actualActorClaims );
    }

    IAuthenticationInfo? IAuthenticationInfoType.FromJObject( JObject? o ) => AuthenticationInfoFromJObject( o );

    ClaimsIdentityAnonymousNotAuthenticated? IAuthenticationInfoType.ToClaimsIdentity( IAuthenticationInfo? info, bool userInfoOnly ) => AuthenticationInfoToClaimsIdentity( info, userInfoOnly );

    JObject? IAuthenticationInfoType.ToJObject( IAuthenticationInfo? info ) => AuthenticationInfoToJObject( info );

    void IAuthenticationInfoType.Write( BinaryWriter w, IAuthenticationInfo? info )
    {
        if( w == null ) throw new ArgumentNullException( nameof( w ) );
        if( info == null ) w.Write( 0 );
        else
        {
            w.Write( 1 );
            int flag = 0;
            if( info!.IsImpersonated ) flag |= 1;
            if( info.Expires.HasValue ) flag |= 2;
            if( info.CriticalExpires.HasValue ) flag |= 4;
            if( info.DeviceId.Length > 0 ) flag |= 8;
            w.Write( (byte)flag );
            UserInfo.Write( w, info.UnsafeUser );
            if( info.IsImpersonated ) UserInfo.Write( w, info.UnsafeActualUser );
            if( info.Expires.HasValue ) w.Write( info.Expires.Value.ToBinary() );
            if( info.CriticalExpires.HasValue ) w.Write( info.CriticalExpires.Value.ToBinary() );
            if( info.DeviceId.Length > 0 ) w.Write( info.DeviceId );
            WriteAuthenticationInfoRemainder( w, info );
        }
    }

    IAuthenticationInfo? IAuthenticationInfoType.Read( BinaryReader r )
    {
        if( r == null ) throw new ArgumentNullException( nameof( r ) );
        try
        {
            int version = r.ReadInt32();
            if( version == 0 ) return null;
            int flags = r.ReadByte();
            IUserInfo? user = UserInfo.Read( r );
            IUserInfo? actualUser = null;
            DateTime? expires = null;
            DateTime? criticalExpires = null;
            if( (flags & 1) != 0 ) actualUser = UserInfo.Read( r );
            if( (flags & 2) != 0 ) expires = DateTime.FromBinary( r.ReadInt64() );
            if( (flags & 4) != 0 ) criticalExpires = DateTime.FromBinary( r.ReadInt64() );
            string deviceId = (flags & 8) != 0 ? r.ReadString() : String.Empty;
            return ReadAuthenticationInfoRemainder( r, actualUser, user, expires, criticalExpires, deviceId );
        }
        catch( Exception ex )
        {
            throw new InvalidDataException( "Invalid binary format.", ex );
        }
    }

    /// <summary>
    /// Implements <see cref="IAuthenticationInfoType.Create"/>.
    /// </summary>
    /// <param name="user">The unsafe user information.</param>
    /// <param name="expires">When null or already expired, Level is <see cref="AuthLevel.Unsafe"/>.</param>
    /// <param name="criticalExpires">Optional critical expiration.</param>
    /// <param name="deviceId">Optional device identifier.</param>
    /// <returns>The authentication information.</returns>
    protected virtual IAuthenticationInfo CreateAuthenticationInfo( IUserInfo? user, DateTime? expires, DateTime? criticalExpires, string? deviceId )
    {
        return user == null && String.IsNullOrEmpty( deviceId )
                ? _none.Value
                : new StdAuthenticationInfo( this, user, expires, criticalExpires, deviceId );
    }

    /// <summary>
    /// Implements <see cref="IAuthenticationInfoType.ToJObject(IAuthenticationInfo)"/>.
    /// </summary>
    /// <param name="info">The authentication information.</param>
    /// <returns>Authentication information as a JObject.</returns>
    protected virtual JObject? AuthenticationInfoToJObject( IAuthenticationInfo? info )
    {
        if( info == null ) return null;
        var o = new JObject();
        o.Add( new JProperty( UserKeyType, UserInfoToJObject( info.UnsafeUser ) ) );
        if( info.IsImpersonated ) o.Add( new JProperty( ActualUserKeyType, UserInfoToJObject( info.UnsafeActualUser ) ) );
        if( info.Expires.HasValue ) o.Add( new JProperty( ExpirationKeyType, info.Expires ) );
        if( info.CriticalExpires.HasValue ) o.Add( new JProperty( CriticalExpirationKeyType, info.CriticalExpires ) );
        if( info.DeviceId.Length > 0 ) o.Add( new JProperty( DeviceIdKeyType, info.DeviceId ) );
        return o;
    }

    /// <summary>
    /// Implements <see cref="IAuthenticationInfoType.FromJObject(JObject)"/>.
    /// </summary>
    /// <param name="o">The JObject.</param>
    /// <returns>The authentication information.</returns>
    protected virtual IAuthenticationInfo? AuthenticationInfoFromJObject( JObject? o )
    {
        if( o == null ) return null;
        try
        {
            var user = UserInfoFromJObject( (JObject?)o[UserKeyType] );
            var actualUser = UserInfoFromJObject( (JObject?)o[ActualUserKeyType] );
            var expires = (DateTime?)o[ExpirationKeyType];
            var criticalExpires = (DateTime?)o[CriticalExpirationKeyType];
            var deviceId = (string?)o[DeviceIdKeyType];
            return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires, deviceId );
        }
        catch( Exception ex )
        {
            throw new InvalidDataException( o.ToString( Formatting.None ), ex );
        }
    }

    /// <inheritdoc cref="IAuthenticationInfoType.ToClaimsIdentity(IAuthenticationInfo?, bool)"/>
    protected virtual ClaimsIdentityAnonymousNotAuthenticated? AuthenticationInfoToClaimsIdentity( IAuthenticationInfo? info, bool userInfoOnly )
    {
        if( info == null ) return null;
        var id = userInfoOnly
                    ? new ClaimsIdentityAnonymousNotAuthenticated( UserInfoToClaims( info.User ), ClaimAuthenticationTypeSimple, UserNameKeyType, null )
                    : new ClaimsIdentityAnonymousNotAuthenticated( UserInfoToClaims( info.UnsafeUser ), ClaimAuthenticationType, UserNameKeyType, null );
        ClaimsIdentityAnonymousNotAuthenticated propertyBearer = id;
        if( !userInfoOnly )
        {
            if( info.IsImpersonated )
            {
                id.Actor = propertyBearer = new ClaimsIdentityAnonymousNotAuthenticated( UserInfoToClaims( info.UnsafeActualUser ), ClaimAuthenticationType, UserNameKeyType, null );
            }
            propertyBearer.AddClaim( new Claim( AuthLevelKeyType, info.Level.ToString() ) );
        }
        if( info.Expires.HasValue ) propertyBearer.AddClaim( new Claim( ExpirationKeyType, info.Expires.Value.ToUnixTimeSeconds().ToString() ) );
        if( info.CriticalExpires.HasValue ) propertyBearer.AddClaim( new Claim( CriticalExpirationKeyType, info.CriticalExpires.Value.ToUnixTimeSeconds().ToString() ) );
        if( info.DeviceId.Length > 0 ) propertyBearer.AddClaim( new Claim( DeviceIdKeyType, info.DeviceId ) );
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
    /// <param name="deviceId">The device identifier.</param>
    /// <param name="id">The claims identity (its AuthenticationType is either <see cref="ClaimAuthenticationType"/> or <see cref="ClaimAuthenticationTypeSimple"/>).</param>
    /// <param name="actualActorClaims">
    /// The <see cref="ClaimsIdentity.Actor"/> claims when impersonation is active,
    /// otherwise it is the <paramref name="id"/>'s Claims.
    /// </param>
    /// <returns>The authentication information.</returns>
    protected virtual IAuthenticationInfo AuthenticationInfoFromClaimsIdentity(
        IUserInfo? actualUser,
        IUserInfo? user,
        DateTime? expires,
        DateTime? criticalExpires,
        string? deviceId,
        ClaimsIdentity id,
        IEnumerable<Claim> actualActorClaims )
    {
        return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires, deviceId );
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
    /// <param name="deviceId">Already read device identifier.</param>
    /// <returns>The authentication info.</returns>
    private IAuthenticationInfo ReadAuthenticationInfoRemainder( BinaryReader r, IUserInfo? actualUser, IUserInfo? user, DateTime? expires, DateTime? criticalExpires, string deviceId )
    {
        return new StdAuthenticationInfo( this, actualUser, user, expires, criticalExpires, deviceId );
    }

    #endregion

}
