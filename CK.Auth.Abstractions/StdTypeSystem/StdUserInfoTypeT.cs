using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace CK.Auth
{
    public abstract class StdUserInfoType<TUserInfo> : IUserInfoType<TUserInfo>
        where TUserInfo : StdUserInfo
    {
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


        // The lazy here is used to defer the actual call to CreateAnonymous
        // after the initialization by the constructors chain when specializing this.
        readonly Lazy<TUserInfo> _anonymous;

        /// <summary>
        /// Initializes a new <see cref="StdUserInfoType{T}"/>.
        /// </summary>
        public StdUserInfoType()
        {
            _anonymous = new Lazy<TUserInfo>( CreateAnonymous, LazyThreadSafetyMode.PublicationOnly );
        }

        /// <summary>
        /// Gets the anonymous user.
        /// </summary>
        public TUserInfo Anonymous => _anonymous.Value;

        /// <summary>
        /// Creates a <typeparamref name="TUserInfo"/> from set of claims (or null if <paramref name="claims"/> is null).
        /// This default implementation extracts standard claims named <see cref="UserIdKeyType"/>, <see cref="UserNameKeyType"/> and <see cref="SchemesKeyType"/>,
        /// and then calls the extension point <see cref="UserInfoFromClaims"/> to handle any extra
        /// fields and create the actual user info object.
        /// </summary>
        /// <param name="claims"></param>
        /// <returns></returns>
        public virtual TUserInfo FromClaims( IEnumerable<Claim> claims )
        {
            if( claims == null ) return null;
            int userId = 0;
            string userName = null;
            IUserSchemeInfo[] schemes = null;
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

        /// <summary>
        /// Implements the last step of <see cref="FromClaims(IEnumerable{Claim})"/>.
        /// </summary>
        /// <param name="userId">The value read from <see cref="UserIdKeyType"/> claim.</param>
        /// <param name="userName">The value read from <see cref="UserNameKeyType"/> claim.</param>
        /// <param name="schemes">The Array read from <see cref="SchemesKeyType"/> claim.</param>
        /// <param name="claims">All the Claims (including the 3 already extracted ones).</param>
        /// <returns>The user information.</returns>
        protected abstract TUserInfo UserInfoFromClaims(int userId, string userName, IUserSchemeInfo[] schemes, IEnumerable<Claim> claims);

        /// <summary>
        /// Implements <see cref="IUserInfoType.ToJObject(IUserInfo)"/>.
        /// </summary>
        /// <param name="info">The user information.</param>
        /// <returns>User information as a JObject.</returns>
        public virtual JObject ToJObject( TUserInfo info )
        {
            if( info == null ) return null;
            return new JObject(
                    new JProperty( UserIdKeyType, info.UserId ),
                    new JProperty( UserNameKeyType, info.UserName ),
                    new JProperty( SchemesKeyType, ToSchemesJArray( info.Schemes ) ) );
        }

        /// <summary>
        /// Creates a <typeparamref name="TUserInfo"/> from a JObject (or null if <paramref name="o"/> is null).
        /// This default implementation handles error (by always throwing a <see cref="InvalidDataException"/>)
        /// and extracts standard fields named <see cref="UserIdKeyType"/>, <see cref="UserNameKeyType"/> and <see cref="SchemesKeyType"/>,
        /// and then calls the extension point <see cref="UserInfoFromJObject"/> to handle any extra
        /// fields and create the actual user info object.
        /// </summary>
        /// <param name="o">The JSON object.</param>
        /// <returns>The extracted user info or null if <paramref name="o"/> is null.</returns>
        /// <exception cref="InvalidDataException">
        /// Whenever the object is not in the expected format.
        /// </exception>
        public virtual TUserInfo FromJObject( JObject o )
        {
            if( o == null ) return null;
            try
            {
                var userId = (int)o[UserIdKeyType];
                if( userId == 0 ) return _anonymous.Value;
                var userName = (string)o[UserNameKeyType];
                JToken t = o[SchemesKeyType];
                var schemes = t.Select( p => new StdUserSchemeInfo( (string)p["name"], (DateTime)p["lastUsed"] ) ).ToArray();
                return UserInfoFromJObject( userId, userName, schemes, o );
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
        /// <param name="userId">The already read user identifier.</param>
        /// <param name="userName">The already read userName.</param>
        /// <param name="schemes">The already read schemes array.</param>
        /// <param name="o">The JObject that may be used to extract any extra field.</param>
        /// <returns>The user information.</returns>
        protected abstract TUserInfo UserInfoFromJObject( int userId, string userName, StdUserSchemeInfo[] schemes, JObject o );

        /// <summary>
        /// Implements <see cref="IUserInfoType.ToClaims(IUserInfo)"/> by returning 
        /// three claims (<see cref="UserNameKeyType"/>, <see cref="UserIdKeyType"/> and <see cref="SchemesKeyType"/>)
        /// in the list.
        /// <param name="info">The user information.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> object or null if info is null.</returns>
        public virtual List<Claim> ToClaims( TUserInfo info )
        {
            if( info == null ) return null;
            var list = new List<Claim>();
            list.Add( new Claim( UserNameKeyType, info.UserName ) );
            list.Add( new Claim( UserIdKeyType, info.UserId.ToString() ) );
            list.Add( new Claim( SchemesKeyType, ToSchemesJArray( info.Schemes ).ToString( Formatting.None ) ) );
            return list;
        }


        /// <summary>
        /// Writes the user information in binary format.
        /// <paramref name="info"/> must be a <typeparamref name="TUserInfo"/> otherwise an <see cref="ArgumentException"/> is thrown.
        /// </summary>
        /// <param name="w">The binary writer (must not be null).</param>
        /// <param name="info">The user info to write that must be a <typeparamref name="TUserInfo"/>. Can be null.</param>
        public virtual void Write( BinaryWriter w, TUserInfo info )
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

        /// <summary>
        /// Implements <see cref="IUserInfoType.Write(BinaryWriter, IUserInfo)"/>.
        /// Only extra fields to <see cref="IUserInfo"/> should be written here.
        /// </summary>
        /// <param name="w">The binary writer.</param>
        /// <param name="info">The user info to write.</param>
        protected abstract void WriteUserInfoRemainder( BinaryWriter w, TUserInfo info );

        /// <summary>
        /// Creates a <typeparamref name="TUserInfo"/> from a binary reader.
        /// This default implementation reads the basic <see cref="IUserInfo"/> data
        /// and then calls the extension point <see cref="ReadUserInfoRemainder"/> to handle any extra
        /// fields and create the actual user info object.
        /// </summary>
        /// <param name="w">The binary writer (must not be null).</param>
        /// <param name="info">The user info to write. Can be null.</param>
        public TUserInfo Read( BinaryReader r )
        {
            if( r == null ) throw new ArgumentNullException( nameof( r ) );
            try
            {
                int version = r.ReadInt32();
                if( version == 0 ) return null;
                int userId = r.ReadInt32();
                string name = r.ReadString();
                int schemeCount = r.ReadInt32();
                IUserSchemeInfo[] schemes = Array.Empty<IUserSchemeInfo>();
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
        /// Implements the last step of <see cref="Read(BinaryReader)"/>.
        /// Basic fields of <see cref="IUserInfo"/> are already read.
        /// </summary>
        /// <param name="r">The binary reader.</param>
        /// <param name="userId">Already read user identifier.</param>
        /// <param name="userName">Already read user name.</param>
        /// <param name="schemes">Already read providers.</param>
        /// <returns>The user info.</returns>
        protected abstract TUserInfo ReadUserInfoRemainder( BinaryReader r, int userId, string userName, IUserSchemeInfo[] schemes );

        /// <summary>
        /// Must create the anonymous object.
        /// </summary>
        /// <returns>The anonymous object.</returns>
        protected abstract TUserInfo CreateAnonymous();

        /// <summary>
        /// Helpers to get providers from a JArray of {name:..., lastUsed:...} objects..
        /// </summary>
        /// <param name="a">Jarray to convert.</param>
        /// <returns>An array of providers.</returns>
        protected virtual IUserSchemeInfo[] FromSchemesJArray( JArray a )
                    => a.Select( p => new StdUserSchemeInfo( (string)p["name"], (DateTime)p["lastUsed"] ) ).ToArray();

        /// <summary>
        /// Helpers to get a JArray from <see cref="IUserInfo.Schemes"/>.
        /// </summary>
        /// <param name="schemes">The schemes.</param>
        /// <returns>A JArray of {name:..., lastUsed:...} objects.</returns>
        protected virtual JArray ToSchemesJArray( IEnumerable<IUserSchemeInfo> schemes )
                    => new JArray( schemes.Select(
                                    p => new JObject( new JProperty( "name", p.Name ), new JProperty( "lastUsed", p.LastUsed ) ) ) );


    }
}
