using System.Net;

namespace Shared.Services
{
    public class AutoRefreshTokenHandler : DelegatingHandler
    {
        private readonly IHttpClientFactory _factory;

        public AutoRefreshTokenHandler(IHttpClientFactory factory)
        {
            _factory = factory;
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Gửi lần 1
            var response = await base.SendAsync(request, cancellationToken);

            // Nếu 401 thì refresh
            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                var refreshClient = _factory.CreateClient("AuthClient");

                var refreshResponse = await refreshClient.GetAsync("/refresh-token");

                if (!refreshResponse.IsSuccessStatusCode)
                    return response;

                request.Headers.Remove("Cookie");
                return await base.SendAsync(request, cancellationToken);
            }

            return response;
        }
    }
}
