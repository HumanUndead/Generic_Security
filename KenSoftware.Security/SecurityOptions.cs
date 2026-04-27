using System;
using System.Collections.Generic;
using System.Text;

namespace KenSoftware.Security
{
    public class SecurityOptions
    {
        public TimeSpan DefaultTtl { get; set; } = TimeSpan.FromMinutes(5);
    }
}
