using System;

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
        readonly IUserInfo _anonymous;

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/>.
        /// </summary>
        /// <param name="anonymous">The anonymous user.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <see cref="DateTime.UtcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after <see cref="DateTime.UtcNow"/> in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
        public StdAuthenticationInfo(IUserInfo anonymous, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires)
            : this( anonymous, actualUser, user, expires, criticalExpires, DateTime.UtcNow)
        {
        }

        /// <summary>
        /// Initializes a new <see cref="StdAuthenticationInfo"/> with a specific "current" date and time.
        /// This constructor should be used in specific scenario (unit testing id one of them).
        /// </summary>
        /// <param name="anonymous">The anonymous user. Must be a valid anonymous.</param>
        /// <param name="actualUser">The actual user. Can be null.</param>
        /// <param name="user">The user. Can be null.</param>
        /// <param name="expires">Expiration must occur after <see cref="DateTime.UtcNow"/> otherwise <see cref="Level"/> is <see cref="AuthLevel.Unsafe"/>.</param>
        /// <param name="criticalExpires">Expiration must occur after <see cref="DateTime.UtcNow"/> in order for <see cref="Level"/> to be <see cref="AuthLevel.Critical"/>.</param>
        /// <param name="utcNow">The "current" date and time.</param>
        public StdAuthenticationInfo(IUserInfo anonymous, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, DateTime utcNow)
        {
            if (anonymous == null || anonymous.ActorId != 0 || anonymous.DisplayName != string.Empty)
                throw new ArgumentException("Invalid anonymous IUserInfo.", nameof(anonymous));
            if (user == null)
            {
                if (actualUser != null) user = actualUser;
                else user = actualUser = anonymous;
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
                    user = actualUser;
                    level = AuthLevel.Unsafe;
                }
                else
                {
                    if (criticalExpires.HasValue)
                    {
                        if (criticalExpires.Value.Kind == DateTimeKind.Local) throw new ArgumentException("Kind must be Utc or Unspecified, not Local.", nameof(criticalExpires));
                        if (criticalExpires.Value <= utcNow) criticalExpires = null;
                        else if (criticalExpires.Value.Kind == DateTimeKind.Unspecified) criticalExpires = DateTime.SpecifyKind(criticalExpires.Value, DateTimeKind.Utc);
                    }
                    level = criticalExpires.HasValue ? AuthLevel.Critical : AuthLevel.Normal;
                }
            }
            _anonymous = anonymous;
            _user = user;
            _actualUser = actualUser;
            _expires = expires;
            _criticalExpires = criticalExpires;
            _level = level;
        }

        /// <summary>
        /// Protected raw constructor. Caution: No checks are done at all.
        /// </summary>
        /// <param name="anonymous">The anonymous.</param>
        /// <param name="actualUser">The actual user.</param>
        /// <param name="user">The user.</param>
        /// <param name="expires">Expiration date.</param>
        /// <param name="criticalExpires">Critical expiration date.</param>
        /// <param name="level">The authentication level.</param>
        protected StdAuthenticationInfo(IUserInfo anonymous, IUserInfo actualUser, IUserInfo user, DateTime? expires, DateTime? criticalExpires, AuthLevel level)
        {
            _anonymous = anonymous;
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
        public IUserInfo User => _level != AuthLevel.Unsafe ? _user : _anonymous;

        /// <summary>
        /// Gets the actual user identifier that has been authenticate when <see cref="Level"/> is 
        /// <see cref="AuthLevel.Normal"/> or <see cref="AuthLevel.Critical"/>.
        /// (When Level is <see cref="AuthLevel.None"/> or <see cref="AuthLevel.Unsafe"/>, this actual user 
        /// property is the anonymous.)
        /// </summary>
        public IUserInfo ActualUser => _level != AuthLevel.Unsafe ? _actualUser : _anonymous;

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
        /// or <see cref="CriticalExpires"/> are greater than <paramref name="utcNow"/>.
        /// </summary>
        /// <param name="utcNow">The "current" date and time to challenge.</param>
        /// <returns>This or an updated authentication information.</returns>
        public StdAuthenticationInfo CheckExpiration(DateTime utcNow)
        {
            if (utcNow.Kind != DateTimeKind.Utc) throw new ArgumentException("Kind must be Utc.", nameof(utcNow));
            var level = _level;
            if( level < AuthLevel.Normal 
                || (level == AuthLevel.Critical && _criticalExpires.Value > utcNow) )
            {
                return this;
            }
            if( _expires.Value > utcNow )
            {
                if( level == AuthLevel.Normal ) return this;
                return new StdAuthenticationInfo(_anonymous, _actualUser, _user, _expires, null, AuthLevel.Normal);
            }
            return new StdAuthenticationInfo(_anonymous, _actualUser, _user, null, null, AuthLevel.Unsafe);
        }

        /// <summary>
        /// Handles expiration checks by returning an updated information whenever <see cref="Expires"/>
        /// or <see cref="CriticalExpires"/> are greater than <see cref="DateTime.UtcNow"/>.
        /// </summary>
        /// <returns>This or an updated authentication information.</returns>
        public StdAuthenticationInfo CheckExpiration() => CheckExpiration(DateTime.UtcNow);

        IAuthenticationInfo IAuthenticationInfo.CheckExpiration(DateTime utcNow) => CheckExpiration(utcNow);
    }
}
