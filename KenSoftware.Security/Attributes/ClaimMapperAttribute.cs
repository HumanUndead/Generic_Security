namespace Qimmah.Security.Attributes
{
    [AttributeUsage(AttributeTargets.Property)]
    public class ClaimMapperAttribute : Attribute
    {
        public string ClaimType { get; }
        public ClaimMapperAttribute(string ClaimType)
        {
            this.ClaimType = ClaimType;
        }
    }
}