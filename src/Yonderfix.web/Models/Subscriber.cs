namespace Yonderfix.web.Models
{
    public class Subscriber
    {
        public string Did { get; set; } = string.Empty;
        public string Handle { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string ProfilePictureUrl { get; set; } = string.Empty;
        public bool FollowsMeBack { get; set; }
        public bool IsFollowedByMe { get; set; }
        public string? MyFollowRecordUri { get; set; } // URI of the record of the authenticated user following this subscriber
    }
}
