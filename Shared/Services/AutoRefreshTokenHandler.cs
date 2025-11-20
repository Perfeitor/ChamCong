using System.Net;

namespace Shared.Services
{
    public class AutoRefreshTokenHandler : DelegatingHandler
    {
        private readonly IHttpClientFactory _factory;
        private static readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);

        public AutoRefreshTokenHandler(IHttpClientFactory factory)
        {
            _factory = factory;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                await _refreshLock.WaitAsync(cancellationToken);
                try
                {
                    var secondRequest = await CloneRequest(request);
                    var secondTry = await base.SendAsync(secondRequest, cancellationToken);

                    if (secondTry.StatusCode != HttpStatusCode.Unauthorized)
                    {
                        return secondTry;
                    }

                    var refreshClient = _factory.CreateClient("AuthClient");
                    var refreshResponse = await refreshClient.GetAsync("/refresh-token", cancellationToken);

                    if (!refreshResponse.IsSuccessStatusCode)
                    {
                        return response;
                    }

                    request.Headers.Remove("Cookie");

                    var finalRequest = await CloneRequest(request);
                    return await base.SendAsync(finalRequest, cancellationToken);
                }
                finally
                {
                    _refreshLock.Release();
                }
            }

            return response;
        }

        private async Task<HttpRequestMessage> CloneRequest(HttpRequestMessage original)
        {
            var clone = new HttpRequestMessage(original.Method, original.RequestUri);

            foreach (var header in original.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (original.Content != null)
            {
                var bytes = await original.Content.ReadAsByteArrayAsync();
                clone.Content = new ByteArrayContent(bytes);

                foreach (var header in original.Content.Headers)
                {
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            return clone;
        }
    }
}
