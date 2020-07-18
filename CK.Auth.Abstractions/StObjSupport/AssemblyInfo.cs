using System;

//
// This enables the StdAuthenticationTypeSystem that is a ISingletonAutoService to be handled by
// CK.StObj automatic DI.
//
[assembly: CK.Setup.IsModelDependent()]
namespace CK.Setup { class IsModelDependentAttribute : Attribute { } }
