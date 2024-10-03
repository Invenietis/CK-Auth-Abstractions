using System;
using System.Diagnostics;

namespace CK.Auth;


/// <summary>
/// Standard immutable implementation of <see cref="IAuthenticationInfo"/>.
/// </summary>
public class StdAuthenticationInfo : IAuthenticationInfo
{
    readonly IUserInfo _actualUser;
    readonly IUserInfo _user;
    readonly DateTime? _expires;
    readonly DateTime? _criticalExpires;
    readonly AuthLevel _level;
    readonly string _deviceId;
    readonly IAuthenticationTypeSystem _typeSystem;

    /// <summary>
    /// Initializes a new <see cref="StdAuthenticationInfo"/>.
    /// </summary>
    /// <param name="typeSystem">The type system.</param>
    /// <param name="user">The user (and actual user).</param>
    /// <param name="expires">Expiration of authentication.</param>
    /// <param name="criticalExpires">Expiration of critical authentication.</param>
    /// <param name="deviceId">Device identifier. When not set <see cref="DeviceId"/> will default to the empty string.</param>
    public StdAuthenticationInfo( IAuthenticationTypeSystem typeSystem, IUserInfo? user, DateTime? expires = null, DateTime? criticalExpires = null, string? deviceId = null )
        : this( typeSystem, user, null, expires, criticalExpires, deviceId, DateTime.UtcNow )
    {
    }

    /// <summary>
    /// Initializes a new <see cref="StdAuthenticationInfo"/> with all its possible data.
    /// </summary>
    /// <param name="typeSystem">The type system.</param>
    /// <param name="actualUser">The actual user.</param>
    /// <param name="user">The user.</param>
    /// <param name="expires">Expiration must occur after <see cref="DateTime.UtcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
    /// <param name="criticalExpires">Expiration must occur after DateTime.UtcNow in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
    /// <param name="deviceId">Device identifier. When not set <see cref="DeviceId"/> will default to the empty string.</param>
    public StdAuthenticationInfo( IAuthenticationTypeSystem typeSystem, IUserInfo? actualUser, IUserInfo? user, DateTime? expires, DateTime? criticalExpires, string? deviceId = null )
        : this( typeSystem, actualUser, user, expires, criticalExpires, deviceId, DateTime.UtcNow )
    {
    }

    /// <summary>
    /// Initializes a new <see cref="StdAuthenticationInfo"/> with a specific "current" date and time.
    /// This constructor should be used in specific scenario (unit testing is one of them).
    /// </summary>
    /// <param name="typeSystem">The type system. Must not be null.</param>
    /// <param name="actualUser">The actual user. Can be null.</param>
    /// <param name="user">The user. Can be null.</param>
    /// <param name="expires">Expiration must occur after <paramref name="utcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
    /// <param name="criticalExpires">Expiration must occur after <paramref name="utcNow"/> in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
    /// <param name="deviceId">Device identifier. When not set <see cref="DeviceId"/> will default to the empty string.</param>
    /// <param name="utcNow">The "current" date and time.</param>
    public StdAuthenticationInfo( IAuthenticationTypeSystem typeSystem, IUserInfo? actualUser, IUserInfo? user, DateTime? expires, DateTime? criticalExpires, string? deviceId, DateTime utcNow )
    {
        if( typeSystem == null ) throw new ArgumentNullException( nameof( typeSystem ) );
        _deviceId = deviceId ?? String.Empty;
        if( user == null )
        {
            if( actualUser != null ) user = actualUser;
            else user = actualUser = typeSystem.UserInfo.Anonymous;
        }
        else
        {
            if( actualUser == null ) actualUser = user;
        }
        AuthLevel level;
        if( actualUser.UserId == 0 )
        {
            user = actualUser;
            expires = null;
            criticalExpires = null;
            level = AuthLevel.None;
        }
        else
        {
            if( actualUser != user && actualUser.UserId == user.UserId )
            {
                user = actualUser;
            }
            if( expires.HasValue )
            {
                if( expires.Value.Kind == DateTimeKind.Local ) throw new ArgumentException( "Kind must be Utc or Unspecified, not Local.", nameof( expires ) );
                if( expires.Value <= utcNow ) expires = null;
                else if( expires.Value.Kind == DateTimeKind.Unspecified ) expires = DateTime.SpecifyKind( expires.Value, DateTimeKind.Utc );
            }
            if( !expires.HasValue )
            {
                expires = null;
                criticalExpires = null;
                level = AuthLevel.Unsafe;
            }
            else
            {
                if( criticalExpires.HasValue )
                {
                    if( criticalExpires.Value.Kind == DateTimeKind.Local ) throw new ArgumentException( "Kind must be Utc or Unspecified, not Local.", nameof( criticalExpires ) );
                    if( criticalExpires.Value <= utcNow ) criticalExpires = null;
                    else
                    {
                        if( criticalExpires.Value.Kind == DateTimeKind.Unspecified ) criticalExpires = DateTime.SpecifyKind( criticalExpires.Value, DateTimeKind.Utc );
                        if( criticalExpires.Value > expires.Value ) criticalExpires = expires;
                    }
                }
                level = criticalExpires.HasValue ? AuthLevel.Critical : AuthLevel.Normal;
            }
        }
        _typeSystem = typeSystem;
        _user = user;
        _actualUser = actualUser;
        _expires = expires;
        _criticalExpires = criticalExpires;
        _level = level;
    }

    /// <inheritdoc />
    public IUserInfo User => _level != AuthLevel.Unsafe ? _user : _typeSystem.UserInfo.Anonymous;

    /// <inheritdoc />
    public IUserInfo ActualUser => _level != AuthLevel.Unsafe ? _actualUser : _typeSystem.UserInfo.Anonymous;

    /// <inheritdoc />
    public IUserInfo UnsafeUser => _user;

    /// <inheritdoc />
    public IUserInfo UnsafeActualUser => _actualUser;

    /// <inheritdoc />
    public AuthLevel Level => _level;

    /// <inheritdoc />
    public DateTime? Expires => _expires;

    /// <inheritdoc />
    public DateTime? CriticalExpires => _criticalExpires;

    /// <inheritdoc />
    public bool IsImpersonated => _user != _actualUser;

    /// <inheritdoc />
    public string DeviceId => _deviceId;

    /// <summary>
    /// Handles expiration checks by returning an updated information whenever <see cref="Expires"/>
    /// or <see cref="CriticalExpires"/> are greater than <see cref="DateTime.UtcNow"/>.
    /// </summary>
    /// <returns>This or an updated authentication information.</returns>
    public StdAuthenticationInfo CheckExpiration() => CheckExpiration( DateTime.UtcNow );

    IAuthenticationInfo IAuthenticationInfo.ClearImpersonation( DateTime utcNow ) => ClearImpersonation( utcNow );

    IAuthenticationInfo IAuthenticationInfo.Impersonate( IUserInfo user, DateTime utcNow ) => Impersonate( user, utcNow );

    IAuthenticationInfo IAuthenticationInfo.CheckExpiration( DateTime utcNow ) => CheckExpiration( utcNow );

    IAuthenticationInfo IAuthenticationInfo.SetExpires( DateTime? expires, DateTime utcNow ) => SetExpires( expires, utcNow );

    IAuthenticationInfo IAuthenticationInfo.SetCriticalExpires( DateTime? criticalExpires, DateTime utcNow ) => SetCriticalExpires( criticalExpires, utcNow );

    IAuthenticationInfo IAuthenticationInfo.SetDeviceId( string deviceId, DateTime utcNow ) => SetDeviceId( deviceId, utcNow );

    /// <inheritdoc cref="IAuthenticationInfo.ClearImpersonation(DateTime)"/>
    public StdAuthenticationInfo ClearImpersonation( DateTime utcNow )
    {
        return IsImpersonated
                ? Clone( _actualUser, _actualUser, _expires, _criticalExpires, _deviceId, utcNow )
                : CheckExpiration( utcNow );
    }

    /// <inheritdoc cref="IAuthenticationInfo.Impersonate(IUserInfo, DateTime)"/>
    public StdAuthenticationInfo Impersonate( IUserInfo user, DateTime utcNow )
    {
        if( user == null ) user = _typeSystem.UserInfo.Anonymous;
        if( _actualUser.UserId == 0 ) throw new InvalidOperationException();
        return _user != user
                ? Clone( _actualUser, user, _expires, _criticalExpires, _deviceId, utcNow )
                : CheckExpiration( utcNow );
    }

    /// <inheritdoc cref="IAuthenticationInfo.CheckExpiration(DateTime)"/>
    public StdAuthenticationInfo CheckExpiration( DateTime utcNow )
    {
        if( utcNow.Kind != DateTimeKind.Utc ) throw new ArgumentException( "Kind must be Utc.", nameof( utcNow ) );
        var level = _level;
        Debug.Assert( level != AuthLevel.Critical || _criticalExpires.HasValue, "Critical level => _criticalExpires !== null" );
        if( level < AuthLevel.Normal
            || (level == AuthLevel.Critical && _criticalExpires!.Value > utcNow) )
        {
            return this;
        }
        Debug.Assert( _expires.HasValue );
        if( _expires!.Value > utcNow )
        {
            if( level == AuthLevel.Normal ) return this;
            Debug.Assert( level == AuthLevel.Critical );
            return Clone( _actualUser, _user, _expires, null, _deviceId, utcNow );
        }
        return Clone( _actualUser, _user, null, null, _deviceId, utcNow );
    }

    /// <inheritdoc cref="IAuthenticationInfo.SetExpires(DateTime?, DateTime)"/>
    public StdAuthenticationInfo SetExpires( DateTime? expires, DateTime utcNow )
    {
        return expires != _expires
                ? Clone( _actualUser, _user, expires, _criticalExpires, _deviceId, utcNow )
                : CheckExpiration( utcNow );
    }

    /// <inheritdoc cref="IAuthenticationInfo.SetCriticalExpires(DateTime?, DateTime)"/>
    public StdAuthenticationInfo SetCriticalExpires( DateTime? criticalExpires, DateTime utcNow )
    {
        if( criticalExpires == _criticalExpires ) return CheckExpiration( utcNow );
        DateTime? newExp = _expires;
        if( criticalExpires.HasValue && (!newExp.HasValue || newExp.Value < criticalExpires.Value) )
        {
            newExp = criticalExpires;
        }
        return Clone( _actualUser, _user, newExp, criticalExpires, _deviceId, utcNow );
    }

    /// <inheritdoc cref="IAuthenticationInfo.SetDeviceId(string, DateTime)" />
    public StdAuthenticationInfo SetDeviceId( string deviceId, DateTime utcNow )
    {
        return _deviceId != deviceId
                ? Clone( _actualUser, _user, _expires, _criticalExpires, deviceId, utcNow )
                : CheckExpiration( utcNow );
    }

    /// <summary>
    /// Extension point required to handle specialization of this class.
    /// Methods like <see cref="Impersonate"/> or <see cref="SetExpires"/> call 
    /// this instead of StdAuthenticationInfo constructor to allow specializations to 
    /// handle extra fields and return the actual specialized type.
    /// </summary>
    /// <param name="actualUser">The new actual user.</param>
    /// <param name="user">The new user.</param>
    /// <param name="expires">The new expires time.</param>
    /// <param name="criticalExpires">The new critical expires time.</param>
    /// <param name="deviceId">The new device identifier.</param>
    /// <param name="utcNow">The "current" date and time to challenge.</param>
    /// <returns>New authentication info.</returns>
    protected virtual StdAuthenticationInfo Clone( IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, string? deviceId, DateTime utcNow )
    {
        return new StdAuthenticationInfo( _typeSystem, actualUser, user, expires, criticalExpires, deviceId, utcNow );
    }
}
