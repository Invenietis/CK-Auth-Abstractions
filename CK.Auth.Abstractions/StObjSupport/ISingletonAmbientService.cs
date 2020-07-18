using System;
using System.Collections.Generic;
using System.Text;

namespace CK.Auth.StObjSupport
{
    /// <summary>
    /// Interface marker definition for singleton services for <see cref="IAuthenticationTypeSystem"/>.
    /// The name of the interface is enough and is defined here because CK.StObj.Model must not
    /// be a dependency of this abstract package.
    /// This ISingletonAutoService uses "duck typing" and it is not required that it extends the IAutoService base interface.
    /// </summary>
    public interface ISingletonAutoService
    {
    }
}
