using System;

//
// This enables the StdAuthenticationTypeSystem that is a ISingletonAmbientService to be handled by
// CK.StObj automatic DI.
//
[assembly: CK.Setup.IsModelDependent()]
namespace CK.Setup { class IsModelDependentAttribute : Attribute { } }
