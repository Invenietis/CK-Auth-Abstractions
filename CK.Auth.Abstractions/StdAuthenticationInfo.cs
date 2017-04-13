using System;
using System.Diagnostics;

namespace CK.Auth
{

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
        readonly IAuthenticationTypeSystem _typeSystem;

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/> with <see cref="AuthLevel.Unsafe"/> level.
        /// </summary>
        /// <param name="typeSystem">The type system. Must not be null.</param>
        /// <param name="user">The user (and actual user). Can be null.</param>
        public StdAuthenticationInfo(IAuthenticationTypeSystem typeSystem, IUserInfo user)
            : this(typeSystem, user, null, null, null, DateTime.MinValue)
        {
        }

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/> with <see cref="AuthLevel.Normal"/> level
        /// (if <paramref name="expires"/> is in the future).
        /// </summary>
        /// <param name="typeSystem">The type system. Must not be null.</param>
        /// <param name="user">The user (and actual user). Can be null.</param>
        /// <param name="expires">Expiration of authentication.</param>
        public StdAuthenticationInfo(IAuthenticationTypeSystem typeSystem, IUserInfo user, DateTime expires)
            : this(typeSystem, user, null, expires, null, DateTime.UtcNow)
        {
        }

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/> with <see cref="AuthLevel.Critical"/> level
        /// (if <paramref name="expires"/> and <paramref name="criticalExpires"/> are in the future).
        /// </summary>
        /// <param name="typeSystem">The type system. Must not be null.</param>
        /// <param name="user">The user (and actual user). Can be null.</param>
        /// <param name="expires">Expiration of authentication.</param>
        /// <param name="criticalExpires">Expiration of critical authentication.</param>
        public StdAuthenticationInfo(IAuthenticationTypeSystem typeSystem, IUserInfo user, DateTime expires, DateTime criticalExpires)
            : this(typeSystem, user, null, expires, criticalExpires, DateTime.UtcNow)
        {
        }

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/> with all its possible data.
        /// </summary>
        /// <param name="typeSystem">The type system. Must not be null.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <see cref="DateTime.UtcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after DateTime.UtcNow in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
        public StdAuthenticationInfo(IAuthenticationTypeSystem typeSystem, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires)
            : this(typeSystem, actualUser, user, expires, criticalExpires, DateTime.UtcNow)
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
        /// <param name="utcNow">The "current" date and time.</param>
        public StdAuthenticationInfo(IAuthenticationTypeSystem typeSystem, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow)
        {
            if (typeSystem == null ) throw new ArgumentNullException(nameof(typeSystem));
            if (user == null)
            {
                if (actualUser != null) user = actualUser;
                else user = actualUser = typeSystem.UserInfo.Anonymous;
            }
            else
            {
                if (actualUser == null) actualUser = user;
            }
            AuthLevel level;
            if (actualUser.ActorId == 0)
            {
                user = actualUser;
                expires = null;
                criticalExpires = null;
                level = AuthLevel.None;
            }
            else
            {
                if (actualUser != user && actualUser.ActorId == user.ActorId)
                {
                    user = actualUser;
                }
                if( expires.HasValue )
                {
                    if (expires.Value.Kind == DateTimeKind.Local) throw new ArgumentException("Kind must be Utc or Unspecified, not Local.", nameof(expires));
                    if (expires.Value <= utcNow) expires = null;
                    else if( expires.Value.Kind == DateTimeKind.Unspecified ) expires = DateTime.SpecifyKind(expires.Value, DateTimeKind.Utc );
                }
                if (!expires.HasValue)
                {
                    expires = null;
                    criticalExpires = null;
                    level = AuthLevel.Unsafe;
                }
                else
                {
                    if (criticalExpires.HasValue)
                    {
                        if (criticalExpires.Value.Kind == DateTimeKind.Local) throw new ArgumentException("Kind must be Utc or Unspecified, not Local.", nameof(criticalExpires));
                        if (criticalExpires.Value <= utcNow) criticalExpires = null;
                        else
                        {
                            if (criticalExpires.Value.Kind == DateTimeKind.Unspecified) criticalExpires = DateTime.SpecifyKind(criticalExpires.Value, DateTimeKind.Utc);
                            if (criticalExpires.Value > expires.Value) criticalExpires = expires;
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

        /// <summary>
        /// Gets the user information itself when <see cref="Level"/> is <see cref="AuthLevel.Normal"/> 
        /// or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this User property 
        /// is the anonymous.)
        /// </summary>
        public IUserInfo User => _level != AuthLevel.Unsafe ? _user : _typeSystem.UserInfo.Anonymous;

        /// <summary>
        /// Gets the actual user identifier that has been authenticate when <see cref="Level"/> is 
        /// <see cref="AuthLevel.Normal"/> or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this actual user 
        /// property is the anonymous.)
        /// </summary>
        public IUserInfo ActualUser => _level != AuthLevel.Unsafe ? _actualUser : _typeSystem.UserInfo.Anonymous;

        /// <summary>
        /// Gets the user information itself whatever <see cref="Level"/> is.
        /// </summary>
        public IUserInfo UnsafeUser => _user;

        /// <summary>
        /// Gets the actual user identifier that has been authenticate whatever <see cref="Level"/> is.
        /// </summary>
        public IUserInfo UnsafeActualUser => _actualUser;

        /// <summary>
        /// Gets the authentication level of this authentication information.
        /// </summary>
        public AuthLevel Level => _level;

        /// <summary>
        /// The expiration time for this authentication.
        /// </summary>
        public DateTime? Expires => _expires;

        /// <summary>
        /// The expiration time for critical authentication level.
        /// </summary>
        public DateTime? CriticalExpires => _criticalExpires;

        /// <summary>
        /// Gets whether the actual user is actually 
        /// impersonated (<see cref="User"/> is not the same as <see cref="ActualUser"/>).
        /// </summary>
        public bool IsImpersonated => _user != _actualUser;

        /// <summary>
        /// Handles expiration checks by returning an updated information whenever <see cref="Expires"/>
        /// or <see cref="CriticalExpires"/> are greater than <see cref="DateTime.UtcNow"/>.
        /// </summary>
        /// <returns>This or an updated authentication information.</returns>
        public StdAuthenticationInfo CheckExpiration() => CheckExpiration(DateTime.UtcNow);

        IAuthenticationInfo IAuthenticationInfo.ClearImpersonation(DateTime utcNow) => ClearImpersonation(utcNow);

        IAuthenticationInfo IAuthenticationInfo.Impersonate(IUserInfo user, DateTime utcNow) => Impersonate(user, utcNow);

        IAuthenticationInfo IAuthenticationInfo.CheckExpiration(DateTime utcNow) => CheckExpiration(utcNow);

        IAuthenticationInfo IAuthenticationInfo.SetExpires(DateTime? expires, DateTime utcNow) => SetExpires(expires, utcNow);

        IAuthenticationInfo IAuthenticationInfo.SetCriticalExpires(DateTime? criticalExpires, DateTime utcNow) => SetCriticalExpires(criticalExpires, utcNow);

        /// <summary>
        /// Removes impersonation if any (the <see cref="ActualUser"/> becomes the <see cref="User"/>).
        /// </summary>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>This or a new authentication info object.</returns>
        public StdAuthenticationInfo ClearImpersonation(DateTime utcNow)
        {
            return IsImpersonated 
                    ? Clone(_actualUser, _actualUser, _expires, _criticalExpires, utcNow)
                    : CheckExpiration(utcNow);
        }

        /// <summary>
        /// Impersonates this <see cref="ActualUser"/>: the <see cref="User"/> will be the new one.
        /// Calling this on the anonymous MUST throw an <see cref="InvalidOperationException"/>.
        /// </summary>
        /// <param name="user">The new impersonated user.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>This or a new new authentication info object.</returns>
        public StdAuthenticationInfo Impersonate(IUserInfo user, DateTime utcNow)
        {
            if (user == null) user = _typeSystem.UserInfo.Anonymous;
            if (_actualUser.ActorId == 0) throw new InvalidOperationException();
            return _user != user
                    ? Clone(_actualUser, user, _expires, _criticalExpires, utcNow)
                    : CheckExpiration(utcNow);
        }

        /// <summary>
        /// Handles expiration checks by returning an updated information whenever <see cref="Expires"/>
        /// or <see cref="CriticalExpires"/> are greater than <paramref name="utcNow"/>.
        /// </summary>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>This or an updated authentication information.</returns>
        public StdAuthenticationInfo CheckExpiration(DateTime utcNow)
        {
            if (utcNow.Kind != DateTimeKind.Utc) throw new ArgumentException("Kind must be Utc.", nameof(utcNow));
            var level = _level;
            if (level < AuthLevel.Normal
                || (level == AuthLevel.Critical && _criticalExpires.Value > utcNow))
            {
                return this;
            }
            if (_expires.Value > utcNow)
            {
                if (level == AuthLevel.Normal) return this;
                Debug.Assert(level == AuthLevel.Critical);
                return Clone(_actualUser, _user, _expires, null, utcNow);
            }
            return Clone(_actualUser, _user, null, null, utcNow);
        }

        /// <summary>
        /// Returns a new authentication information with <see cref="Expires"/> sets
        /// to the new value (or this authentication info if it is the same).
        /// </summary>
        /// <param name="expires">The new <see cref="Expires"/> value.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>The updated authentication info.</returns>
        public StdAuthenticationInfo SetExpires(DateTime? expires, DateTime utcNow)
        {
            return expires != _expires
                    ? Clone(_actualUser, _user, expires, _criticalExpires, utcNow)
                    : CheckExpiration(utcNow);
        }

        /// <summary>
        /// Returns a new authentication information with <see cref="CriticalExpires"/> sets
        /// to the new value (or this authentication info if it is the same).
        /// If the new <paramref name="criticalExpires"/> is greater than <see cref="Expires"/>,
        /// the new Expires is automatically boosted to the new critical expires time. 
        /// </summary>
        /// <param name="criticalExpires">The new CriticalExpires value.</param>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>The updated authentication info.</returns>
        public StdAuthenticationInfo SetCriticalExpires(DateTime? criticalExpires, DateTime utcNow)
        {
            if( criticalExpires == _criticalExpires ) return CheckExpiration(utcNow);
            DateTime? newExp = _expires;
            if( criticalExpires.HasValue && (!newExp.HasValue || newExp.Value < criticalExpires.Value ) )
            {
                newExp = criticalExpires;
            }
            return Clone(_actualUser, _user, newExp, criticalExpires, utcNow);
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
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>New authentication info.</returns>
        protected virtual StdAuthenticationInfo Clone(IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow )
        {
            return new StdAuthenticationInfo(_typeSystem, actualUser, user, expires, criticalExpires, utcNow);
        }
    }
}
