# JE.IdentityServer.Security

## An OWIN Middleware component for an OpenIdConnect endpoint that provides the following a set of security features

Currently targets IdentityServer3 v2.

### TL;DR

### Features

A set of OWIN middleware components providing the following features:

* Google Recaptcha for OpenIdConnect

* Throttling for logins

#### Throttling for OpenIdConnect native logins

In order to register the middleware for throttling, you should register your implementation of *ILoginStatistics* with your IoC container (see below) and inject this into the middleware as a factory lambda method.
Your implementation of ILoginStatistics must implement **IDisposable** and the lifetime of this object will be managed per OWIN request.

```cs
app.UsePerOwinContext<ILoginStatistics>(() => new ImplementationOfLoginStatistics());

app.UseThrottlingForAuthenticationRequests(new IdentityServerThrottlingOptions
{
    ProtectedPath = "/identity/connect/token",
    NumberOfAllowedLoginFailures = 3,
    ExcludedUsernameExpressions = _excludedUsernameExpressions,
    ProtectedGrantTypes = new string[] { "password" },
});

// Register IdentityServer
app.Map("/identity", idsrvApp => idsrvApp.UseIdentityServer(IdentityServerBootstrap.CreateStartupOptions()));
```

*IdentityServerThrottlingOptions* is used to configure the middleware on bootstrap and provides the following parameters:

| Parameter                      | Default         | Description  |
| ------------------------------ |-----------------|--------------|
| ProtectedPath                  | /identity/connnect/token | Path to protect |
| NumberOfAllowedLoginFailures   | 0               | Number of allowed login failures before throttling requests |
| ExcludedUsernameExpressions    | empty list      | A list of regexes that allows you to skip throttling and reporting for specific email addresses eg load testing accounts | 
| ProtectedGrantTypes            | empty list      | A list of protected grant types that should be throttled eg native vs social login |

#### Injecting your own services with your favourite container

```cs

var middlewareOptions = new IdentityServerThrottlingOptions
{
// some options
};

var container = new MyContainer();  // eg. StructureMap in this case
appBuilder.UsePerOwinContext(() => container.GetInstance<ILoginStatistics>());

appBuilder.UseThrottlingForAuthenticationRequests(middlewareOptions);

```


### How to contribute

See [CONTRIBUTING.md](CONTRIBUTING.md).

### How to release
See [CONTRIBUTING.md](CONTRIBUTING.md).

