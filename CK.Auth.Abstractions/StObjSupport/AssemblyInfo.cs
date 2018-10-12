using System;

//
// This enables the StdAuthenticationTypeSystem that is a ISingletonAmbientService to be handled by
// CK.StObj automatic DI.
//
[assembly: CK.Setup.IsModel()]
namespace CK.Setup { class IsModelAttribute : Attribute { } }
