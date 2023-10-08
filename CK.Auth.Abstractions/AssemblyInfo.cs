
//
// This enables the StdAuthenticationTypeSystem that is a ISingletonAutoService to be handled by
// CK.StObj automatic DI (and the IAuthenticationInfo to be a ubiquitous endpoint scoped service).
[assembly: CK.Setup.IsModelDependent()]
