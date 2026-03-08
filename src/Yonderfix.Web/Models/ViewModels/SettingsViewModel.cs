using System.ComponentModel.DataAnnotations;

namespace Yonderfix.Web.Models.ViewModels;

public class SettingsViewModel
{
    [Range(5, 100, ErrorMessage = "Page size must be between 5 and 100")]
    [Display(Name = "Items Per Page")]
    public int PageSize { get; set; } = 20;

    public string? SuccessMessage { get; set; }
}
