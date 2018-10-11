using System;
using System.Collections.Generic;
using System.Text;

namespace CK.Auth
{
    /// <summary>
    /// Interface marker definition for singleton services for <see cref="IAuthenticationTypeSystem"/>.
    /// The name of the interface is enough and is defined here because CK.StObj.Model must not
    /// be a dependency of this abstract package.
    /// </summary>
    public interface ISingletonAmbientService
    {
    }
}
