using Microsoft.AspNetCore.DataProtection;

namespace KenSoftware.Security
{
    public class DataProtectionBuilderOptions
    {
        public IDataProtectionBuilder Builder { get; }

        public DataProtectionBuilderOptions(IDataProtectionBuilder builder)
        {
            Builder = builder;
        }

        public DataProtectionBuilderOptions PersistKeysToFileSystem(string path)
        {
            Builder.PersistKeysToFileSystem(new DirectoryInfo(path));
            return this;
        }

        public DataProtectionBuilderOptions SetKeyLifetime(TimeSpan lifetime)
        {
            Builder.SetDefaultKeyLifetime(lifetime);
            return this;
        }
    }
}
