using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;

namespace CK.Auth
{
    /// <summary>
    /// This class fixes the default <see cref="ClaimsIdentity.IsAuthenticated"/> that is false
    /// if and only if the <see cref="ClaimsIdentity.AuthenticationType"/> is null or empty.
    /// This specialization adds a simple rule: the <see cref="ClaimsIdentity.Name"/> should also
    /// not be null or empty.
    /// <para>
    /// The issue is that this IsAuthenticated property is used in security filters like the one
    /// behind the [Authorize] attribute. This implementation is safer than the default one since
    /// it considers that a user with an empty name is NOT authenticated.
    /// </para>
    /// </summary>
    public class ClaimsIdentityAnonymousNotAuthenticated : ClaimsIdentity
    {
        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated()
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( string authenticationType )
            : base( authenticationType )
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( BinaryReader reader )
            : base( reader )
        {
        }

        public ClaimsIdentityAnonymousNotAuthenticated( IIdentity identity )
            : base( identity )
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( IEnumerable<Claim> claims )
            : base( claims )
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( IEnumerable<Claim> claims, string authenticationType )
            : base( claims, authenticationType )
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( IIdentity identity, IEnumerable<Claim> claims )
            : base( identity, claims )
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( string authenticationType, string nameType, string roleType )
            : base( authenticationType, nameType, roleType )
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( IEnumerable<Claim> claims, string authenticationType, string nameType, string roleType )
            : base( claims, authenticationType, nameType, roleType )
        {
        }

        /// <inheritdoc />
        public ClaimsIdentityAnonymousNotAuthenticated( IIdentity identity, IEnumerable<Claim> claims, string authenticationType, string nameType, string roleType )
            : base( identity, claims, authenticationType, nameType, roleType )
        {
        }

        /// <inheritdoc />
        protected ClaimsIdentityAnonymousNotAuthenticated( ClaimsIdentity other )
            : base( other )
        {
        }

        /// <summary>
        /// Gets whether this identity has been authenticated by calling the base <see cref="ClaimsIdentity.IsAuthenticated"/>
        /// and checking that this <see cref="ClaimsIdentity.Name"/> is not null nor empty.
        /// </summary>
        public override bool IsAuthenticated => base.IsAuthenticated && !string.IsNullOrEmpty( Name );
    }
}
