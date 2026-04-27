using Microsoft.Extensions.DependencyInjection;

namespace KenSoftware.Security
{
    public static class SecurityProvider
    {
        private static IServiceProvider _provider;

        public static void Configure(IServiceProvider provider)
        {
            _provider = provider;
        }

        public static ISecureDataService SecureData =>
            _provider.GetRequiredService<ISecureDataService>();
    }
}
