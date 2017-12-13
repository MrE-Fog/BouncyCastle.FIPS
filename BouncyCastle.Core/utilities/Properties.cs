
namespace Org.BouncyCastle.Utilities
{
    /// <summary>Utility method for accessing system properties.</summary>
    public static class Properties
    {
        /// <summary>
        /// Return true if the environment variable propertyName has the value "true".
        /// </summary>
        /// <param name="propertyName">The name of the property to check</param>
        /// <returns>true if the environment variable propertyName is "true", false otherwise.</returns>
        public static bool IsOverrideSet(string propertyName)
        {
            string env = Platform.GetEnvironmentVariable(propertyName);
            return env != null && Platform.EqualsIgnoreCase("true", env);
        }
    }
}
