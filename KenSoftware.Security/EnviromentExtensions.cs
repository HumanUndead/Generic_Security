using System;
using System.Collections.Generic;
using System.Text;

namespace KenSoftware.Security
{
    public static class EnviromentExtensions
    {
        public static string GetEnv(string key, string defaultValue = null)
        {
            var value = Environment.GetEnvironmentVariable(key);
            return string.IsNullOrEmpty(value) ? defaultValue : value;
        }

        public static int GetEnvInt(string key, int defaultValue)
        {
            return int.TryParse(GetEnv(key), out var result) ? result : defaultValue;
        }

        public static TimeSpan GetEnvTimeSpan(string key, TimeSpan defaultValue)
        {
            return TimeSpan.TryParse(GetEnv(key), out var result) ? result : defaultValue;
        }
    }
}
