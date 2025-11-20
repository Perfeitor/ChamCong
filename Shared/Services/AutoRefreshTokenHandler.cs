using System.Net;

namespace Shared.Services
{
    public class RefreshTokenHandler : DelegatingHandler
    {
        private readonly IHttpClientFactory _factory;
        private static readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);

        public RefreshTokenHandler(IHttpClientFactory factory)
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
                    var secondTry = await base.SendAsync(CloneRequest(request), cancellationToken);

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

                    return await base.SendAsync(CloneRequest(request), cancellationToken);
                }
                finally
                {
                    _refreshLock.Release();
                }
            }

            return response;
        }

        private HttpRequestMessage CloneRequest(HttpRequestMessage original)
        {
            var clone = new HttpRequestMessage(original.Method, original.RequestUri);

            foreach (var header in original.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (original.Content != null)
            {
                clone.Content = new StreamContent(original.Content.ReadAsStream());
                foreach (var header in original.Content.Headers)
                {
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            return clone;
        }
    }
}
