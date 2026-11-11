using System.Net;
using OmniRecovery.Core;

namespace OmniRecovery.Infrastructure.Discovery;

/// <summary>Explicit, unauthenticated loopback-only reachability check; never follows redirects.</summary>
public static class SiteReachability
{
    public static async Task<Finding> CheckAsync(string? address,CancellationToken cancellationToken=default)
    {
        if(!Uri.TryCreate(address,UriKind.Absolute,out var uri)||uri.Scheme is not ("http" or "https")||!string.IsNullOrEmpty(uri.UserInfo)||!string.IsNullOrEmpty(uri.Query)||!string.IsNullOrEmpty(uri.Fragment)
            ||!(uri.Host.Equals("localhost",StringComparison.OrdinalIgnoreCase)||(IPAddress.TryParse(uri.Host.Trim('[',']'),out var ip)&&IPAddress.IsLoopback(ip))))
            return new("HTTP_SCOPE","Select a credential-free loopback HTTP/HTTPS administrator URL for this optional check.",VerificationStatus.Unsupported);
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);timeout.CancelAfter(TimeSpan.FromSeconds(8));
        using var handler=new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false,UseDefaultCredentials=false,UseProxy=false};
        using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(8)};
        try
        {
            using var request=new HttpRequestMessage(HttpMethod.Head,uri);
            using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
            var status=(int)response.StatusCode;
            return new("HTTP_REACHABILITY",$"Unauthenticated HEAD returned HTTP {status}. This verifies an HTTP response, not Joomla login or PHP/database health. Redirects were not followed.",status<400?VerificationStatus.Accessible:VerificationStatus.Unavailable);
        }
        catch(OperationCanceledException) when(!cancellationToken.IsCancellationRequested){return new("HTTP_TIMEOUT","The selected local HTTP endpoint did not respond within eight seconds.",VerificationStatus.Unavailable);}
        catch(HttpRequestException){return new("HTTP_UNAVAILABLE","The selected local HTTP endpoint could not be reached or its TLS certificate could not be verified. No certificate checks were bypassed.",VerificationStatus.Unavailable);}
    }
}
