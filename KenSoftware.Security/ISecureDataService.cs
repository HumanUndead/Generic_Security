using System;
using System.Collections.Generic;
using System.Text;

namespace KenSoftware.Security
{
    public interface ISecureDataService
    {
        string Encrypt(string plaintext, TimeSpan? ttl = null);
        string Decrypt(string protectedData);
        T Decrypt<T>(string protectedData);
    }
}
