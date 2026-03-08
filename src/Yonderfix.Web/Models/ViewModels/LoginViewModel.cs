using System.ComponentModel.DataAnnotations;

namespace Yonderfix.Web.Models.ViewModels;

public class LoginViewModel
{
    [Required(ErrorMessage = "Handle is required")]
    [Display(Name = "Bluesky Handle")]
    public string Handle { get; set; } = string.Empty;

    [Required(ErrorMessage = "App password is required")]
    [Display(Name = "App Password")]
    public string AppPassword { get; set; } = string.Empty;

    public string? ErrorMessage { get; set; }
}
