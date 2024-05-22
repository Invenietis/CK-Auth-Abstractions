using CK.Core;
using System.Threading.Tasks;

namespace CK.Auth
{
    /// <summary>
    /// Singleton context-less service that is able to read or synthetize a <see cref="IUserInfo"/>
    /// from its identifier.
    /// </summary>
    public interface IUserInfoProvider : ISingletonAutoService
    {
        /// <summary>
        /// Obtains a <see cref="IUserInfo"/> from its identifier.
        /// </summary>
        /// <param name="monitor">The monitor to use.</param>
        /// <param name="userId">The user identifier.</param>
        /// <returns>The user information.</returns>
        ValueTask<IUserInfo> GetUserInfoAsync( IActivityMonitor monitor, int userId );
    }
}
