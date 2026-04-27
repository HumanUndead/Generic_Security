using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

namespace KenSoftware.Security
{

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddKenSecurity(
            this IServiceCollection services,
            string appName,
            Action<DataProtectionBuilderOptions>? configure = null)
        {
            var builder = services.AddDataProtection()
                .SetApplicationName(appName);
            configure?.Invoke(new DataProtectionBuilderOptions(builder));

            services.AddSingleton<ISecureDataService, SecureDataService>();

            return services;
        }
    }
}
